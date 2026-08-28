#!/usr/bin/env python3
"""Tests for the overnight watchdog + recovery playbook (plan todo 16).

Pure-logic TDD suite: the watchdog runs as an INDEPENDENT process (never a
thread of overnight.py — oracle r1), so every hardware/system boundary is
injected: clock, process probe, console PING, readers(), journalctl,
systemctl, pyserial RTS pulse, USB rebind. No real system calls, no network,
no serial, no pcscd.

Load-bearing properties under test:
  * dead-man switch fires at EXACT thresholds (pid dead / heartbeat stale)
    and rebuilds the morning report from the partial results.json;
  * bolty recovery sequence ORDER (stop -> rts_pulse_reset -> usb_rescan
    only-if-port-missing -> start -> PING) and the NEVER-REFLASH invariant
    (no esptool / write-flash anywhere in the command sequence);
  * recovery cap 2/night then passive-monitor degrade;
  * pcscd restart cap 3 then degraded row;
  * ABORT file -> cooperative abort flag, the scheduler is NEVER killed;
  * heartbeat file parser for the todo-5 protocol {"pid","ts","phase"}.

Timing model: the watchdog only learns about failures by OBSERVING them on a
poll, so every threshold test first polls once (failure becomes visible),
then advances the clock to the threshold boundary. The heartbeat file is
refreshed before each poll so the dead-man switch never steals the scenario.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/overnight/tests/test_watchdog.py -q
"""

import json
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import watchdog  # noqa: E402
from watchdog import Watchdog, hb_age_s, load_heartbeat  # noqa: E402

SOCK = "/run/bolty/console.sock"
PORT = "/dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0"
PID = 4242


def stops(sysctl):
    return [c for c in sysctl.recovery_commands()
            if c[:2] == ("systemctl", "stop")]

ISO_NOW = datetime(2026, 8, 28, 23, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- fakes ----


class FakeClock:
    """Deterministic clock: sleep advances both monotonic and wall time."""

    def __init__(self, t0=0.0, wall=ISO_NOW.timestamp()):
        self._mono, self._wall = t0, wall

    def monotonic(self):
        return self._mono

    def time(self):
        return self._wall

    def sleep(self, s):
        self._mono += max(0.0, s)
        self._wall += max(0.0, s)

    def advance(self, s):
        self.sleep(s)


class FakeProbe:
    """Injectable scheduler-pid probe; records every signal we send."""

    def __init__(self, alive=True):
        self.alive = alive
        self.signals = []  # (pid, sig)

    def __call__(self, pid):
        if pid is None:
            return None
        self.signals.append((pid, 0))  # watchdog only ever probes (sig 0)
        return self.alive


class FakeSys:
    """Injectable system boundary: PING, systemctl, serial, USB, journalctl."""

    def __init__(self, ping_ok=True, hb_age=5, readers=None, port_ok=True):
        self.ping_ok = ping_ok
        self.hb_age = hb_age
        self.readers_list = readers if readers is not None else \
            ["ACS ACR1252 1S ICC Reader 00 00", "GemPCTwin serial 00 00"]
        self.port_ok = port_ok
        self.calls = []  # every hardware/system interaction, in order

    def ping(self, socket_path=SOCK, timeout=5.0):
        self.calls.append(("ping", socket_path))
        if self.ping_ok:
            return {"hb_age": self.hb_age, "lines": [], "error": None}
        return {"hb_age": None, "lines": [], "error": "ConnectionRefused"}

    def readers(self):
        self.calls.append(("readers",))
        return list(self.readers_list)

    def port_exists(self, port=PORT):
        self.calls.append(("port_exists", port))
        return self.port_ok

    def rts_pulse_reset(self, port=PORT):
        self.calls.append(("rts_pulse_reset", port))

    def usb_rescan(self):
        self.calls.append(("usb_rescan",))

    def systemctl(self, *argv):
        self.calls.append(("systemctl",) + tuple(argv))

    def journalctl(self, units=("pcscd", "bolty-console"), n=50):
        self.calls.append(("journalctl", tuple(units), n))
        return f"-- Journal begins --\nfake snapshot for {units}\n"

    def recovery_commands(self):
        """System/serial commands only (polls excluded) — the reflash-audit
        surface."""
        return [c for c in self.calls if c[0] in
                ("systemctl", "rts_pulse_reset", "usb_rescan")]


def write_hb(tmp_path, clock, phase="WINDOW1", pid=PID):
    """Write a FRESH heartbeat in the todo-5 protocol shape."""
    ts = datetime.fromtimestamp(clock.time(), tz=timezone.utc)
    d = {"pid": pid, "ts": ts.isoformat(), "phase": phase}
    (tmp_path / "heartbeat.json").write_text(json.dumps(d))
    return d


def partial_results(tmp_path, **run_extra):
    """A realistic mid-flight results.json (todo-5 ResultsStore shape)."""
    state = {
        "run": {"started_at": "2026-08-28T22:00:00+00:00", "ended_at": None,
                "dry_run": False, "exit_code": None, "status": "running"},
        "phases": [{"name": "PREFLIGHT", "status": "completed",
                    "started_at": "2026-08-28T22:00:00+00:00",
                    "planned_dur_s": 1800.0, "actual_dur_s": None,
                    "detail": ""}],
        "rows": [{"ts": "2026-08-28T22:31:00+00:00", "mono": 1.0,
                  "phase": "WINDOW1", "lane": "track_a_cycles",
                  "type": "cycle", "status": "PASS", "i": 3}],
        "timeline": [],
        "mode_decision": None,
    }
    state["run"].update(run_extra)
    (tmp_path / "results.json").write_text(json.dumps(state))
    return state


def make_dog(tmp_path, clock, sysctl=None, probe=None, pid=PID, **cfg):
    sysctl = sysctl if sysctl is not None else FakeSys()
    probe = probe if probe is not None else FakeProbe(alive=True)
    dog = Watchdog(
        results_dir=tmp_path,
        clock=clock,
        sysctl=sysctl,
        probe=probe,
        scheduler_pid=pid,
        # compressed intervals so threshold math is exact and fast
        poll_tick_s=1.0, ping_poll_s=1.0, console_dead_s=180.0, hb_gap_s=60.0,
        readers_poll_s=1.0, reader_gone_s=300.0,
        **cfg,
    )
    return dog, sysctl, probe


def poll(dog, clock, tmp_path, *, advance=0.0, phase="WINDOW1"):
    """Advance the clock, refresh the heartbeat (the scheduler's job), then
    run exactly one watchdog iteration."""
    clock.advance(advance)
    write_hb(tmp_path, clock, phase=phase)
    return dog.poll_once()


# ------------------------------------------------------------- heartbeat ----


def test_heartbeat_parser_protocol(tmp_path):
    write_hb(tmp_path, FakeClock(), pid=99, phase="WINDOW2")
    hb = load_heartbeat(tmp_path / "heartbeat.json")
    assert hb["pid"] == 99
    assert hb["phase"] == "WINDOW2"
    assert hb_age_s(hb, FakeClock().time() + 10.0) == 10.0
    # missing / corrupt files parse to None, never raise
    assert load_heartbeat(tmp_path / "nope.json") is None
    (tmp_path / "bad.json").write_text("{not json")
    assert load_heartbeat(tmp_path / "bad.json") is None
    (tmp_path / "bad2.json").write_text(json.dumps({"pid": 1}))  # no ts
    assert load_heartbeat(tmp_path / "bad2.json") is None


def test_heartbeat_freshness_exact_threshold():
    hb = {"pid": 1, "ts": ISO_NOW.isoformat(), "phase": "WINDOW1"}
    now = ISO_NOW.timestamp()
    assert hb_age_s(hb, now + 120.0) == pytest.approx(120.0)     # still fresh
    assert hb_age_s(hb, now + 120.001) == pytest.approx(120.001, abs=1e-3)
    assert hb_age_s(None, now) is None  # missing file handled by caller


# --------------------------------------------------------------- dead-man ----


def test_deadman_no_fire_when_healthy(tmp_path):
    clock = FakeClock()
    dog, _, probe = make_dog(tmp_path, clock)
    for _ in range(30):
        assert poll(dog, clock, tmp_path, advance=10) is not False
    assert dog.done_reason is None
    assert not (tmp_path / "report.md").exists()


def test_deadman_stale_threshold_boundary(tmp_path):
    clock = FakeClock()
    # heartbeat written exactly 120s ago: fresh at 120.0, stale at 121.0
    ts = (ISO_NOW - timedelta(seconds=120)).isoformat()
    (tmp_path / "heartbeat.json").write_text(
        json.dumps({"pid": PID, "ts": ts, "phase": "WINDOW1"}))
    dog, _, _ = make_dog(tmp_path, clock)
    assert dog.deadman.reasons(clock.monotonic(), clock.time()) == []
    clock.advance(1.0)
    assert dog.deadman.reasons(clock.monotonic(), clock.time()) == \
        ["heartbeat_stale"]


def test_deadman_fires_on_dead_pid_with_fresh_hb(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    partial_results(tmp_path)
    dog, _, _ = make_dog(tmp_path, clock, probe=FakeProbe(alive=False))
    assert dog.poll_once() is False  # watchdog exits after handling
    assert dog.done_reason == "scheduler_dead"
    state = json.loads((tmp_path / "results.json").read_text())
    assert state["run"]["scheduler_died_at"]
    assert "scheduler died" in state["run"]["status"]


def test_deadman_missing_hb_grace_then_fire(tmp_path):
    clock = FakeClock()
    dog, _, _ = make_dog(tmp_path, clock)  # no heartbeat file at all
    # scheduler "alive": startup grace holds while it may not have started
    assert dog.deadman.reasons(clock.monotonic() + 119, clock.time() + 119) == []
    # past startup grace (120s) with no heartbeat ever seen: fire
    assert dog.deadman.reasons(clock.monotonic() + 121, clock.time() + 121) == \
        ["heartbeat_missing"]


def test_deadman_generates_partial_report_from_fixture(tmp_path):
    clock = FakeClock()
    ts = (ISO_NOW - timedelta(seconds=121)).isoformat()
    (tmp_path / "heartbeat.json").write_text(
        json.dumps({"pid": PID, "ts": ts, "phase": "WINDOW1"}))
    partial_results(tmp_path)  # mid-flight: one PASS row, PREFLIGHT completed
    dog, sysctl, _ = make_dog(tmp_path, clock)
    assert dog.poll_once() is False
    md = (tmp_path / "report.md").read_text()
    assert "track_a_cycles" in md        # fixture row made it into the report
    assert "scheduler died" in md        # loud status line
    assert "scheduler_dead" in md        # anomaly timeline row
    state = json.loads((tmp_path / "results.json").read_text())
    assert state["run"]["scheduler_died_at"]
    assert "scheduler_dead" in [e["kind"] for e in state["timeline"]]
    # a journalctl snapshot was taken for the anomaly
    assert any(c[0] == "journalctl" for c in sysctl.calls)


def test_scheduler_completion_merges_journal_and_exits(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    partial_results(tmp_path, status="completed", exit_code=0,
                    ended_at=ISO_NOW.isoformat())
    # console down must NOT trigger recovery: the scheduler already finished,
    # the watchdog's remaining job is merge + report + exit
    sysctl = FakeSys(ping_ok=False)
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl,
                              probe=FakeProbe(alive=False))
    assert dog.poll_once() is False
    assert dog.done_reason == "scheduler_completed"
    assert sysctl.recovery_commands() == []  # no recovery after completion
    assert (tmp_path / "report.md").exists()


# ------------------------------------------------------ bolty recovery ----


def test_recovery_sequence_order_and_never_reflash(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    sysctl = FakeSys(ping_ok=False, port_ok=True)
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path)                       # observe the failure
    while not sysctl.recovery_commands():
        assert poll(dog, clock, tmp_path, advance=1.0) is not False
    cmds = sysctl.recovery_commands()
    flat = " ".join(" ".join(map(str, c)) for c in cmds)
    # NEVER-REFLASH invariant (load-bearing: a reflash wipes NVS mid-window)
    for banned in ("esptool", "write-flash", "write_flash", "espflash"):
        assert banned not in flat, f"recovery must never contain {banned}: {cmds}"
    # exact ordering: stop -> rts pulse -> (no usb: port present) -> start
    assert [c[:2] for c in cmds] == [
        ("systemctl", "stop"),
        ("rts_pulse_reset", PORT),
        ("systemctl", "start"),
    ]
    # ...and a PING verify happens after start
    start_i = next(i for i, c in enumerate(sysctl.calls)
                   if c[:2] == ("systemctl", "start"))
    assert any(c[0] == "ping" for c in sysctl.calls[start_i:])


def test_recovery_usb_rescan_only_when_port_missing(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    sysctl = FakeSys(ping_ok=False, port_ok=False)
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path)
    while not sysctl.recovery_commands():
        assert poll(dog, clock, tmp_path, advance=1.0) is not False
    kinds = [c[0] for c in sysctl.recovery_commands()]
    # rescan between the two pulses: the first pulse could not have reached
    # a missing port, so it is repeated after the USB rebind
    assert kinds == ["systemctl", "rts_pulse_reset", "usb_rescan",
                     "rts_pulse_reset", "systemctl"]


def test_recovery_not_before_3min_dead(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    sysctl = FakeSys(ping_ok=False)
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path, advance=0)    # t0: failure first observed
    poll(dog, clock, tmp_path, advance=179)  # dead 179s: below threshold
    assert sysctl.recovery_commands() == []
    poll(dog, clock, tmp_path, advance=1)    # dead exactly 180s: fires
    assert sysctl.recovery_commands()


def test_hb_gap_triggers_recovery_at_exact_threshold(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    # daemon up, firmware heartbeat stale — fires on a single observation
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=FakeSys(
        ping_ok=True, hb_age=60))
    poll(dog, clock, tmp_path)
    assert any(c[:2] == ("systemctl", "stop") for c in sysctl.recovery_commands())
    # one second below the threshold does NOT fire
    clock2 = FakeClock()
    write_hb(tmp_path, clock2)
    dog2, sysctl2, _ = make_dog(tmp_path, clock2, sysctl=FakeSys(
        ping_ok=True, hb_age=59))
    dog2.poll_once()
    assert sysctl2.recovery_commands() == []


def test_recovery_cap_two_then_passive_degrade(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    sysctl = FakeSys(ping_ok=False)
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)

    def episode():
        poll(dog, clock, tmp_path)
        before = len(stops(sysctl))
        while len(stops(sysctl)) == before:
            assert poll(dog, clock, tmp_path, advance=1.0) is not False

    episode()
    episode()
    assert len(stops(sysctl)) == 2
    # third death episode: NO recovery commands, a degrade row, observation
    # keeps running (timeline rows still land)
    poll(dog, clock, tmp_path)
    poll(dog, clock, tmp_path, advance=180)
    assert len(stops(sysctl)) == 2  # no third attempt: passive degrade only
    journal = [json.loads(ln) for ln in
               (tmp_path / "watchdog.jsonl").read_text().splitlines()]
    kinds = [e["kind"] for e in journal]
    assert "recovery_degraded" in kinds
    assert "console_down" in kinds  # kept observing + recording


def test_role_gate_window_is_passive(tmp_path):
    # during ROLE_GATE the switch itself stops/starts the console; the
    # watchdog must not fight it
    clock = FakeClock()
    write_hb(tmp_path, clock, phase="ROLE_GATE")
    sysctl = FakeSys(ping_ok=False, readers=[])
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path, advance=0, phase="ROLE_GATE")
    poll(dog, clock, tmp_path, advance=400, phase="ROLE_GATE")  # way past
    assert sysctl.recovery_commands() == []
    assert not any(c[:2] == ("systemctl", "restart") for c in sysctl.calls)


def test_window2_routes_to_pcscd_not_console(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock, phase="WINDOW2")
    partial_results(tmp_path)  # mode_decision None -> Mode A assumed
    sysctl = FakeSys(ping_ok=False, readers=["ACS ACR1252 1S ICC Reader 00 00"])
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path, advance=0, phase="WINDOW2")
    poll(dog, clock, tmp_path, advance=400, phase="WINDOW2")
    # console recovery never fires (no stop/start/rts/usb); the pcscd restart
    # after 5min of GemPCTwin absence IS the intended playbook here
    assert not any(c[0] in ("rts_pulse_reset", "usb_rescan") or
                   c[:2] in (("systemctl", "stop"), ("systemctl", "start"))
                   for c in sysctl.calls)
    assert any(c[0] == "readers" for c in sysctl.calls)  # pcscd path active


def test_mode_b_window2_still_watches_console(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock, phase="WINDOW2")
    state = partial_results(tmp_path)
    state["mode_decision"] = {"mode": "Mode B — role switch failed; ccid "
                              "deferred to night 2 (fallback)", "ok": False}
    (tmp_path / "results.json").write_text(json.dumps(state))
    sysctl = FakeSys(ping_ok=False, readers=[])
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path, advance=0, phase="WINDOW2")
    poll(dog, clock, tmp_path, advance=181, phase="WINDOW2")
    # bolty role persists in Mode B: console recovery IS the right playbook
    assert any(c[:2] == ("systemctl", "stop") for c in sysctl.recovery_commands())
    # and no pcscd restarts were issued against the absent GemPCTwin
    assert not any(c[:2] == ("systemctl", "restart") for c in sysctl.calls)


# ------------------------------------------------------------- ccid ----


def test_pcscd_restart_only_after_5min_gone(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock, phase="WINDOW2")
    partial_results(tmp_path)
    sysctl = FakeSys(readers=["ACS ACR1252 1S ICC Reader 00 00"])  # no GemPC
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    poll(dog, clock, tmp_path, advance=0, phase="WINDOW2")    # first observed
    poll(dog, clock, tmp_path, advance=299, phase="WINDOW2")  # below 5min
    assert not any(c[:2] == ("systemctl", "restart") for c in sysctl.calls)
    poll(dog, clock, tmp_path, advance=2, phase="WINDOW2")  # 301s >= 300s
    restarts = [c for c in sysctl.calls if c[:2] == ("systemctl", "restart")]
    assert len(restarts) == 1
    assert "pcscd" in " ".join(restarts[0])


def test_pcscd_restart_cap_three_then_degraded(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock, phase="WINDOW2")
    partial_results(tmp_path)
    sysctl = FakeSys(readers=["ACS ACR1252 1S ICC Reader 00 00"])
    dog, sysctl, _ = make_dog(tmp_path, clock, sysctl=sysctl)
    for _ in range(4):  # four 5-minute gone episodes
        poll(dog, clock, tmp_path, advance=0, phase="WINDOW2")    # observe
        poll(dog, clock, tmp_path, advance=301, phase="WINDOW2")  # >= 5min
    restarts = [c for c in sysctl.calls if c[:2] == ("systemctl", "restart")]
    assert len(restarts) == 3  # capped
    journal = [json.loads(ln) for ln in
               (tmp_path / "watchdog.jsonl").read_text().splitlines()]
    assert "recovery_degraded" in [e["kind"] for e in journal]
    assert any(c[0] == "journalctl" for c in sysctl.calls)  # anomaly snapshot


# ------------------------------------------------------------- ABORT ----


def test_abort_file_honored_cooperatively(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    dog, sysctl, probe = make_dog(tmp_path, clock)
    (tmp_path / "ABORT").write_text("")  # operator: touch results/<date>/ABORT
    dog.poll_once()
    flag = tmp_path / "ABORT_REQUESTED"
    assert flag.exists()
    assert json.loads(flag.read_text())["requested_at"]
    # idempotent: a second poll does not rewrite the flag
    mtime = flag.stat().st_mtime_ns
    poll(dog, clock, tmp_path, advance=2)
    assert flag.stat().st_mtime_ns == mtime
    # cooperative only: the scheduler pid received probes (sig 0), never a
    # lethal signal
    assert probe.signals and all(s == (PID, 0) for s in probe.signals)
    assert dog.done_reason is None  # watchdog keeps watching
    journal = [json.loads(ln) for ln in
               (tmp_path / "watchdog.jsonl").read_text().splitlines()]
    assert "abort_requested" in [e["kind"] for e in journal]


def test_never_sends_lethal_signals_whole_run(tmp_path):
    clock = FakeClock()
    ts = (ISO_NOW - timedelta(seconds=121)).isoformat()
    (tmp_path / "heartbeat.json").write_text(
        json.dumps({"pid": PID, "ts": ts, "phase": "WINDOW1"}))
    partial_results(tmp_path)
    probe = FakeProbe(alive=False)
    dog, sysctl, probe = make_dog(tmp_path, clock, probe=probe)
    dog.poll_once()  # dead-man fires, report generates, watchdog exits
    assert all(s[1] == 0 for s in probe.signals)  # probes only, never kills
    assert signal.SIGKILL not in [s[1] for s in probe.signals]


# --------------------------------------------------------- event journal ----


def test_events_append_to_shared_results_and_sidecar(tmp_path):
    clock = FakeClock()
    write_hb(tmp_path, clock)
    dog, _, _ = make_dog(tmp_path, clock)
    dog.journal.event("watchdog_started", level="info", note="hi")
    state = json.loads((tmp_path / "results.json").read_text())
    assert [e["kind"] for e in state["timeline"]] == ["watchdog_started"]
    lines = (tmp_path / "watchdog.jsonl").read_text().splitlines()
    assert len(lines) == 1
    ev = json.loads(lines[0])
    assert ev["kind"] == "watchdog_started"
    assert ev["wd_seq"] == 1
    assert not list(tmp_path.glob("*.tmp"))  # atomic: no temp leftovers


# ------------------------------------------------------------- selftest ----


def test_selftest_runs_clean():
    assert watchdog.run_selftest() is True
