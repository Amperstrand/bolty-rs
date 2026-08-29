#!/usr/bin/env python3
"""Overnight watchdog + recovery playbook (plan todo 16).

Runs as an INDEPENDENT detached process beside the orchestrator (todo 19 arms
it as its own pid — never a thread of overnight.py: a thread dies with the
scheduler, oracle r1). Same results dir, same config.json, stdlib only.

What it watches and what it does:

  1. SCHEDULER DEAD-MAN (Metis): the orchestrator's pid (``--pid`` /
     config / ARMED.json / heartbeat fallback) plus the todo-5 heartbeat file
     ``heartbeat.json`` (``{"pid","ts","phase"}``, freshness <= 120s). If the
     process is dead or the heartbeat is stale, the watchdog merges its event
     journal into the incrementally-persisted ``results.json`` (todo 5 d),
     marks ``run.scheduler_died_at``, regenerates ``report.md`` via
     ``overnight.build_report_md(state)`` (tolerant import — a minimal local
     fallback renders if overnight.py is unavailable) and exits: the user
     always wakes to a report. A CLEANLY FINISHED scheduler (status
     completed/fatal) gets merge + report + exit instead of a death mark.

  2. BOLTY-WINDOW RECOVERY (console PING every 60s; dead >= 3min OR firmware
     HB gap >= 60s): ``sudo systemctl stop bolty-console`` -> rts_pulse_reset
     (REBOOT ONLY — a reflash would wipe NVS mid-window, killing WiFi/token/
     REST track; the DTR-first pyserial block is copied from
     ccid-firmware-rs/tools/switch_role.sh:32-43) -> usb_rescan ONLY if the
     serial port is missing (mirror of switch_role.sh:27-31) -> start
     bolty-console -> verify PING. Hard cap 2 recoveries/night, then
     passive-monitor degrade (keep observing, timeline rows only).

  3. CCID-WINDOW MONITOR (readers() poll 60s): GemPCTwin gone >= 5min ->
     request a pcscd restart via the MARKER PROTOCOL (round-2 amendment): as
     an independent process the watchdog cannot hold overnight.py's global
     pcscd-maintenance lock, so while the scheduler is ALIVE it writes
     ``PCSCD_RESTART_REQUEST`` (the scheduler restarts pcscd.socket/service
     UNDER the lock, switch_role.sh:66 pattern, then atomically consumes the
     request: rename to ``.done`` + delete). Oracle r3: only ACKNOWLEDGED
     requests count — marker consumed OR readers() recovery — and the >= 5min
     gone-timer re-arms after each cycle (no restart loops); an
     unacknowledged marker escalates to a degraded row after 10 min. Only a
     CONFIRMED-DEAD scheduler (pid gone or heartbeat stale — its lanes are
     dead too) permits a direct restart. Cap 3 restarts total, then degraded
     rows. WINDOW2 under Mode B keeps the bolty playbook
     instead (the bolty role persists), so we never issue pointless pcscd
     restarts against a stick that is not a reader (pcscd probing the port is
     the B11 wedge class — issues.md).

  4. EVENT JOURNAL: every event lands in ``watchdog.jsonl`` (append-only
     sidecar, fsync per line) AND best-effort in the shared ``results.json``
     timeline via the todo-5 atomic write-temp+rename protocol (unique tmp
     name — the scheduler's own ``results.json.tmp`` is never touched).
     Anomalies additionally snapshot ``journalctl -u pcscd -u bolty-console
     -n 50`` into the results dir.

  5. ABORT POLL: ``results/<date>/ABORT`` existing means the operator wants
     the night wound down. The watchdog writes ``ABORT_REQUESTED`` (json with
     the request time) which the scheduler honors at its next phase boundary
     (todo-17 integration contract). The watchdog NEVER kills or signals the
     scheduler — ABORT is cooperative only.

  6. Window routing comes from the heartbeat ``phase`` (WINDOW2+ModeA ->
     ccid; ROLE_GATE -> passive, the role switch itself is driving the
     services; everything else -> bolty). All timing goes through an
     injectable clock; every system interaction (systemctl, serial, USB
     rebind, PING socket, readers(), journalctl, pid probe) sits behind an
     injectable boundary so tests run with zero real system calls.

Usage:
    python3 watchdog.py --selftest
    python3 watchdog.py --config results/<date>/config.json [--pid <pid>]
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Tolerant import of the todo-5 orchestrator (same directory). We only need
# two things: build_report_md(state) and ping_daemon(socket). If overnight.py
# is absent or mid-flight, local fallbacks keep the watchdog standalone.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
try:
    import overnight as _overnight  # noqa: F401  (todo 5, same directory)

    _build_report_md = _overnight.build_report_md
    _ping_daemon = _overnight.ping_daemon
except Exception:  # noqa: BLE001 — tolerant per todo-5 protocol, never fatal
    _build_report_md = None
    _ping_daemon = None

DEFAULT_CFG = {
    "poll_tick_s": 10.0,          # dead-man + ABORT cadence
    "hb_fresh_s": 120.0,          # scheduler heartbeat freshness budget
    "startup_grace_s": 120.0,     # heartbeat may not exist yet at arming
    "console_socket": "/run/bolty/console.sock",
    "serial_port": "/dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00"
                   "-port0",
    "ping_poll_s": 60.0,
    "console_dead_s": 180.0,      # PING failing >= 3min -> recover
    "hb_gap_s": 60.0,             # daemon-reported firmware HB gap -> recover
    "recovery_cap": 2,            # then passive-monitor degrade
    "daemon_settle_s": 6.0,       # switch_role.sh:88 settle after start
    "ping_verify_tries": 3,
    "readers_poll_s": 60.0,
    "reader_gone_s": 300.0,        # GemPCTwin absent >= 5min -> restart pcscd
    "pcscd_restart_cap": 3,        # then degraded row (shared across modes)
    "pcscd_settle_s": 10.0,        # switch_role.sh:66 settle after restart
    "marker_timeout_s": 600.0,     # PCSCD_RESTART_REQUEST unhandled -> degrade
    "pcscd_units": ("pcscd.socket", "pcscd.service"),
}

FINISHED_STATUSES = ("completed", "fatal")


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")


def _atomic_write_text(path: Path, text: str) -> None:
    """Write-temp+rename with a WATCHDOG-UNIQUE tmp name, so concurrent
    scheduler persists (results.json.tmp / report.md.tmp) never collide."""
    tmp = path.with_name(path.name + ".wd-tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _atomic_write_json(path: Path, obj) -> None:
    _atomic_write_text(path, json.dumps(obj, indent=1, sort_keys=True))


# ------------------------------------------------------------ heartbeat ----


def load_heartbeat(path) -> dict | None:
    """Parse the todo-5 heartbeat file ``{"pid","ts","phase"}``. Returns None
    on missing/corrupt/incomplete files — never raises (a damaged heartbeat
    is evidence, not a crash)."""
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("ts"), str):
        return None
    return d


def hb_age_s(hb: dict | None, now_wall: float) -> float | None:
    """Age in seconds of a parsed heartbeat; None if not computable."""
    if not hb:
        return None
    try:
        ts = datetime.fromisoformat(hb["ts"])
    except (KeyError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return now_wall - ts.timestamp()


# ------------------------------------------------------- scheduler pid ----


def resolve_scheduler_pid(cli_pid, cfg: dict, results_dir) -> int | None:
    """--pid > config scheduler_pid > ARMED.json (todo-19 attestation) >
    heartbeat pid."""
    for cand in (cli_pid, cfg.get("scheduler_pid"), cfg.get("pid")):
        try:
            if cand:
                return int(cand)
        except (TypeError, ValueError):
            continue
    try:
        armed = json.loads((Path(results_dir) / "ARMED.json").read_text())
        if armed.get("scheduler_pid"):
            return int(armed["scheduler_pid"])
        pids = armed.get("pids") or {}
        if pids.get("scheduler"):
            return int(pids["scheduler"])
    except (OSError, ValueError, TypeError):
        pass
    hb = load_heartbeat(Path(results_dir) / "heartbeat.json")
    if hb and hb.get("pid"):
        return int(hb["pid"])
    return None


def default_pid_probe(pid: int | None) -> bool | None:
    """kill(pid, 0) liveness + /proc cmdline attestation (guards against a
    recycled pid answering for the dead scheduler). Signal 0 only — the
    watchdog never sends a real signal to the scheduler."""
    if not pid:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except OSError:
        return None
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes() \
            .decode("utf-8", "replace")
        if "overnight" not in cmdline:
            return False  # pid was recycled by an unrelated process
    except OSError:
        pass  # /proc unreadable: trust the kill(0) result
    return True


# ------------------------------------------------- real system boundary ----


class RealSys:
    """The default (real) hardware/system boundary. Everything here is what
    tests replace; every method touches the real box, so tests NEVER use this
    class. Mirrors ccid-firmware-rs/tools/switch_role.sh mechanics."""

    def __init__(self, console_socket: str, serial_port: str):
        self.socket = console_socket
        self.port = serial_port

    def ping(self, socket_path=None, timeout: float = 5.0) -> dict:
        fn = _ping_daemon or _local_ping
        return fn(socket_path or self.socket, timeout)

    def readers(self) -> list:
        # pcscd restarts (scheduler-executed PCSCD_RESTART_REQUEST markers)
        # invalidate pyscard's PROCESS-WIDE PCSC context singleton: a stale
        # context would read as "reader gone" and loop restart requests.
        # Renew + retry once (pattern: role_switch.list_readers, 1d227b5).
        from smartcard.System import readers  # pyscard; absent -> disable lane

        try:
            return [str(r) for r in readers()]
        except Exception:
            from smartcard.pcsc.PCSCContext import PCSCContext

            PCSCContext.renewContext()
            return [str(r) for r in readers()]

    def port_exists(self, port=None) -> bool:
        return os.path.exists(port or self.port)

    def rts_pulse_reset(self, port=None) -> None:
        # REBOOT ONLY (never reflash). DTR MUST be cleared before the RTS
        # pulse: pyserial asserts DTR on open, DTR=IO0 low + RTS pulse =
        # chip held in download mode -> dead-silent UART. Verbatim mechanism
        # from switch_role.sh:32-43 ("the frozen firmware afternoon").
        import serial

        s = serial.Serial(port or self.port, 115200, bytesize=8, parity="N",
                          stopbits=2, timeout=0.2)
        s.dtr = False
        s.rts = False
        time.sleep(0.3)
        s.rts = True
        time.sleep(0.15)
        s.rts = False
        s.close()

    def usb_rescan(self) -> None:
        # USB rebind of the stick's port (clears FT232 wedge states),
        # mirroring switch_role.sh usb_rescan (unbind 1-1, settle, bind).
        import subprocess

        for op in ("unbind", "bind"):
            subprocess.run(
                ["sudo", "tee", f"/sys/bus/usb/drivers/usb/{op}"],
                input=b"1-1", check=True, stdout=subprocess.DEVNULL)
            time.sleep(4.0 if op == "unbind" else 6.0)

    def systemctl(self, *argv) -> None:
        import subprocess

        subprocess.run(["sudo", "systemctl", *argv], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    def journalctl(self, units=("pcscd", "bolty-console"), n: int = 50) -> str:
        import subprocess

        cmd = ["sudo", "journalctl"]
        for u in units:
            cmd += ["-u", u]
        cmd += ["-n", str(n), "--no-pager"]
        return subprocess.run(cmd, check=True, capture_output=True,
                              text=True).stdout


def _local_ping(socket_path: str, timeout: float = 5.0) -> dict:
    """Fallback PING when overnight.py is not importable (same protocol as
    overnight.ping_daemon / bolty-console.py PING)."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(socket_path)
        s.sendall(b"PING\n")
        out = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            out += c
        s.close()
        text = out.decode("latin1", "replace")
        import re

        m = re.search(r"hb_age=(-?\d+)s", text)
        return {"hb_age": int(m.group(1)) if m else None,
                "lines": text.splitlines(), "error": None}
    except OSError as e:
        return {"hb_age": None, "lines": [], "error": repr(e)}


class RealClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def time(self) -> float:
        return time.time()

    def sleep(self, s: float) -> None:
        if s > 0:
            time.sleep(s)


# --------------------------------------------------------- event journal ----


class Journal:
    """Append-only sidecar (watchdog.jsonl, fsync per line) + best-effort
    merge into the shared results.json timeline (todo-5 atomic protocol).
    The sidecar is authoritative: the scheduler rewrites results.json from
    its own memory, so watchdog rows are re-merged into the final report."""

    def __init__(self, results_dir, clock, sysctl):
        self.dir = Path(results_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "watchdog.jsonl"
        self.results_path = self.dir / "results.json"
        self.clock, self.sysctl = clock, sysctl
        self._seq = 0

    def event(self, kind: str, level: str = "info", **fields) -> dict:
        self._seq += 1
        ev = {"ts": _iso(self.clock.time()),
              "mono": round(self.clock.monotonic(), 4),
              "kind": kind, "level": level, "wd_seq": self._seq}
        ev.update(fields)
        if level == "anomaly":
            self._snapshot(ev)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, sort_keys=True, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._merge_live(ev)
        return ev

    def anomaly(self, kind: str, **fields) -> dict:
        return self.event(kind, level="anomaly", **fields)

    def _snapshot(self, ev: dict) -> None:
        """journalctl snapshot for anomalies (pcscd | bolty-console -n 50)."""
        try:
            text = self.sysctl.journalctl(("pcscd", "bolty-console"), 50)
            p = self.dir / f"journalctl-{ev['kind']}-{ev['wd_seq']}.log"
            _atomic_write_text(p, text)
            ev["journal_snapshot"] = p.name
        except Exception as e:  # a failed snapshot never loses the event
            ev["journal_snapshot_failed"] = repr(e)

    def _merge_live(self, ev: dict) -> None:
        """Best-effort append into the shared results.json timeline. Losing
        this race to the scheduler is fine (sidecar is authoritative and
        re-merged at report time)."""
        try:
            state = self.load_state()
            timeline = state.setdefault("timeline", [])
            if ev["wd_seq"] not in {e.get("wd_seq") for e in timeline}:
                timeline.append(ev)
            _atomic_write_json(self.results_path, state)
        except OSError:
            pass

    def load_state(self) -> dict:
        """Current shared results.json, or a todo-5-shaped skeleton when
        missing/corrupt (sidecar events survive either way)."""
        return _load_results(self.results_path)

    def merge_sidecar(self, state: dict) -> dict:
        """Fold every sidecar event not already present (by wd_seq) into the
        state's timeline — used when the watchdog renders the final report."""
        timeline = state.setdefault("timeline", [])
        seen = {e.get("wd_seq") for e in timeline}
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("wd_seq") not in seen:
                timeline.append(ev)
                seen.add(ev.get("wd_seq"))
        return state


def _load_results(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"run": {}, "phases": [], "rows": [], "timeline": [],
                "mode_decision": None}


# ------------------------------------------------------------- dead-man ----


class DeadMan:
    """Scheduler liveness: pid probe + heartbeat freshness (<= 120s). The
    startup grace covers the arming race where the watchdog starts before the
    scheduler has written its first heartbeat."""

    def __init__(self, hb_path, pid, probe, *, fresh_s: float,
                 grace_s: float, started_mono: float):
        self.hb_path = Path(hb_path)
        self.pid = pid
        self.probe = probe
        self.fresh_s, self.grace_s = float(fresh_s), float(grace_s)
        self.started_mono = started_mono
        self.ever_saw_hb = False

    def reasons(self, now_mono: float, now_wall: float) -> list:
        """[] while healthy; otherwise the evidence list (non-empty = the
        scheduler is dead or hung — report and exit)."""
        hb = load_heartbeat(self.hb_path)
        if hb is not None:
            self.ever_saw_hb = True
        out = []
        try:
            alive = self.probe(self.pid)
        except Exception:  # noqa: BLE001 — an unreadable pid is not evidence
            alive = None
        if alive is False:
            out.append("process_dead")
        if hb is None:
            if self.ever_saw_hb or (now_mono - self.started_mono) > self.grace_s:
                out.append("heartbeat_missing")
        else:
            age = hb_age_s(hb, now_wall)
            if age is not None and age > self.fresh_s:
                out.append("heartbeat_stale")
        return out


# ------------------------------------------------------ bolty recovery ----


class ConsoleRecovery:
    """bolty-console watchdog: PING every poll; daemon dead >= 3min or a
    firmware HB gap >= 60s triggers the REBOOT-ONLY recovery sequence (never
    a reflash — NVS survives reboots, not reflashes). Cap 2/night, then
    passive monitoring."""

    def __init__(self, sysctl, clock, journal, cfg: dict):
        self.sysctl, self.clock, self.journal = sysctl, clock, journal
        self.socket = cfg["console_socket"]
        self.port = cfg["serial_port"]
        self.poll_s = float(cfg["ping_poll_s"])
        self.dead_s = float(cfg["console_dead_s"])
        self.hb_gap_s = float(cfg["hb_gap_s"])
        self.cap = int(cfg["recovery_cap"])
        self.settle_s = float(cfg["daemon_settle_s"])
        self.verify_tries = int(cfg["ping_verify_tries"])
        self.next_due = 0.0
        self.dead_since = None
        self.gap_pending = False
        self.recoveries = 0
        self.passive = False
        self.degraded_noted = False

    def reset(self) -> None:
        """Leaving the bolty window: drop accumulated failure state (a PING
        failure during the role switch must not trigger a recovery after it)."""
        self.dead_since = None
        self.gap_pending = False

    def poll_if_due(self, now_mono: float) -> None:
        if now_mono < self.next_due:
            return
        self.next_due = now_mono + self.poll_s
        self._observe(self.sysctl.ping(self.socket), now_mono)
        why = self._trigger(now_mono)
        if why is None:
            return
        if self.passive:
            if not self.degraded_noted:
                self.journal.anomaly(
                    "recovery_degraded", component="bolty_console",
                    reason=f"recovery cap {self.cap} reached; passive "
                           f"monitoring only", trigger=why)
                self.degraded_noted = True
            return
        self._recover(why)

    def _observe(self, ping: dict, now_mono: float) -> None:
        if ping.get("error"):
            if self.dead_since is None:
                self.dead_since = now_mono
                self.journal.anomaly("console_down", error=str(ping["error"]))
        else:
            if self.dead_since is not None:
                self.dead_since = None
                self.journal.event("console_back")
            age = ping.get("hb_age")
            if age is not None and age >= self.hb_gap_s:
                self.journal.anomaly("hb_gap", source="daemon_ping",
                                     hb_age_s=age)
                self.gap_pending = True

    def _trigger(self, now_mono: float):
        if self.dead_since is not None and \
                (now_mono - self.dead_since) >= self.dead_s:
            return f"console dead >= {self.dead_s:.0f}s"
        if self.gap_pending:
            self.gap_pending = False
            return f"firmware HB gap >= {self.hb_gap_s:.0f}s"
        return None

    def _recover(self, why: str) -> None:
        """stop -> RTS reboot pulse -> usb_rescan only-if-port-missing ->
        start -> verify PING. REBOOT ONLY: no esptool, no write-flash, ever."""
        self.journal.anomaly("recovery_begin", component="bolty_console",
                             attempt=self.recoveries + 1, trigger=why)
        self.sysctl.systemctl("stop", "bolty-console")
        try:
            self.sysctl.rts_pulse_reset(self.port)
        except Exception as e:  # noqa: BLE001 — recorded, sequence continues
            self.journal.event("rts_pulse_failed", error=repr(e))
        if not self.sysctl.port_exists(self.port):
            self.sysctl.usb_rescan()
            # the first pulse could not have reached a missing port — repeat
            # it after the rebind so the chip actually reboots
            try:
                self.sysctl.rts_pulse_reset(self.port)
            except Exception as e:  # noqa: BLE001
                self.journal.event("rts_pulse_retry_failed", error=repr(e))
        self.sysctl.systemctl("start", "bolty-console")
        self.clock.sleep(self.settle_s)
        ok = False
        for _ in range(self.verify_tries):
            res = self.sysctl.ping(self.socket)
            if not res.get("error"):
                ok = True
                break
            self.clock.sleep(5.0)
        self.recoveries += 1
        self.dead_since = None
        self.journal.anomaly("recovery_result", component="bolty_console",
                             attempt=self.recoveries, ping_ok=ok)
        if self.recoveries >= self.cap:
            self.passive = True


# ---------------------------------------------------------- ccid window ----


class ReaderMonitor:
    """pcscd-side monitor: readers() poll; GemPCTwin gone >= 5min -> request a
    pcscd restart. Round-2 amendment: as an INDEPENDENT process the watchdog
    cannot hold overnight.py's in-process global pcscd-maintenance lock, so
    while the scheduler is ALIVE it never restarts pcscd itself (that would
    kill every reader context without pausing lanes). Instead it writes
    PCSCD_RESTART_REQUEST; the scheduler's monitor executes the restart UNDER
    the lock and atomically consumes the request (rename to .done, delete).
    Oracle r3 ack semantics: the watchdog counts ONLY acknowledged requests —
    marker consumed OR readers() recovery — and re-arms its >= 5min gone-timer
    after each cycle, so a never-cleared marker can never loop restarts; an
    unacknowledged marker times out after 10 min into a degraded row. Only a
    CONFIRMED-DEAD scheduler (pid gone or heartbeat stale — lanes are dead
    too) permits a direct `systemctl restart pcscd`. One restart counter,
    cap 3 across all ack modes + direct, then degraded rows."""

    def __init__(self, sysctl, clock, journal, cfg: dict, *, hb_path,
                 scheduler_pid, probe):
        self.sysctl, self.clock, self.journal = sysctl, clock, journal
        self.poll_s = float(cfg["readers_poll_s"])
        self.gone_s = float(cfg["reader_gone_s"])
        self.cap = int(cfg["pcscd_restart_cap"])
        self.settle_s = float(cfg["pcscd_settle_s"])
        self.units = tuple(cfg["pcscd_units"])
        self.marker_timeout_s = float(cfg["marker_timeout_s"])
        self.hb_path, self.pid, self.probe = Path(hb_path), scheduler_pid, probe
        self.fresh_s = float(cfg["hb_fresh_s"])
        self.marker_path = Path(journal.dir) / "PCSCD_RESTART_REQUEST"
        self.next_due = 0.0
        self.gone_since = None
        self.marker_at = None
        self.restarts = 0
        self.passive = False
        self.degraded_noted = False

    def reset(self) -> None:
        self.gone_since = None

    def scheduler_alive(self) -> bool:
        """The amendment's liveness gate: PID alive AND heartbeat fresh.
        A fresh heartbeat outweighs an unknown pid (probe returned None)."""
        age = hb_age_s(load_heartbeat(self.hb_path), self.clock.time())
        hb_ok = age is not None and age <= self.fresh_s
        try:
            alive = self.probe(self.pid)
        except Exception:  # noqa: BLE001 — an unreadable pid is not evidence
            alive = None
        return hb_ok and alive is not False

    def poll_if_due(self, now_mono: float) -> None:
        if now_mono < self.next_due:
            return
        self.next_due = now_mono + self.poll_s
        try:
            readers = self.sysctl.readers()
            present = any("GemPCTwin" in str(r) for r in readers)
        except Exception as e:  # noqa: BLE001 — pcscd down = transport, not a crash
            present = False
            self.journal.event("readers_error", error=repr(e))
        if present:
            if self.marker_at is not None:
                if self.marker_path.exists():
                    # reader recovered before the scheduler handled it:
                    # retract so no spurious restart is ever executed — the
                    # recovery itself is the acknowledgement (oracle r3)
                    self.marker_path.unlink(missing_ok=True)
                    self.journal.event("marker_retracted",
                                       detail="GemPCTwin returned before the "
                                              "request was handled")
                    self._ack("restart_request_acked", "reader_recovery")
                else:
                    self._ack("pcscd_restart", "scheduler_marker")
            elif self.gone_since is not None:
                self.gone_since = None
                self.journal.event("reader_back")
            return
        if self.gone_since is None:
            self.gone_since = now_mono
            self.journal.anomaly("reader_gone", detail="GemPCTwin not in "
                                                       "readers()")
            return
        if self.marker_at is not None:
            self._poll_marker(now_mono)
            return
        if (now_mono - self.gone_since) < self.gone_s:
            return
        if self.passive:
            if not self.degraded_noted:
                self.journal.anomaly(
                    "recovery_degraded", component="pcscd",
                    reason=f"pcscd restart cap {self.cap} reached; degraded "
                           f"row, observation continues")
                self.degraded_noted = True
            self.gone_since = now_mono  # re-armed; keep observing
            return
        self._request_restart(now_mono)

    def _ack(self, kind: str, via: str) -> None:
        """One acknowledged request cycle: count it, re-arm the >= 5min
        gone-timer (a consumed marker can never loop into back-to-back
        requests), enforce the shared cap."""
        self.restarts += 1
        self.marker_at = None
        self.gone_since = None
        self.journal.anomaly(kind, via=via, attempt=self.restarts)
        if self.restarts >= self.cap:
            self.passive = True

    def _poll_marker(self, now_mono: float) -> None:
        if not self.marker_path.exists():
            # the scheduler atomically consumed the request (rename to .done
            # then delete) after restarting pcscd under its lock — the
            # original path disappearing IS the ack point
            self._ack("pcscd_restart", "scheduler_marker")
        elif (now_mono - self.marker_at) >= self.marker_timeout_s:
            self.journal.anomaly(
                "recovery_degraded", component="pcscd",
                reason=f"PCSCD_RESTART_REQUEST unhandled for "
                       f"{self.marker_timeout_s:.0f}s (scheduler alive but "
                       f"not honoring the marker); never direct-restart "
                       f"while it lives")
            self.passive = True
            self.degraded_noted = True

    def _request_restart(self, now_mono: float) -> None:
        if self.scheduler_alive():
            _atomic_write_json(self.marker_path, {
                "requested_at": _iso(self.clock.time()), "source": "watchdog",
                "reason": f"GemPCTwin absent from readers() for "
                          f">= {self.gone_s:.0f}s",
                "action": "restart pcscd under the global maintenance lock, "
                          "then atomically consume this request (rename to "
                          "PCSCD_RESTART_REQUEST.done, then delete)"})
            self.marker_at = now_mono
            self.journal.anomaly("pcscd_restart_requested",
                                 marker=self.marker_path.name)
            return
        # scheduler CONFIRMED dead: its lanes are dead too, so no live reader
        # context can be harmed — a direct restart is now safe
        self.restarts += 1
        self.journal.anomaly("pcscd_restart", via="direct_scheduler_dead",
                             attempt=self.restarts)
        self.sysctl.systemctl("restart", *self.units)
        self.clock.sleep(self.settle_s)
        self.gone_since = None  # fresh 5-minute window after the restart
        if self.restarts >= self.cap:
            self.passive = True


# ---------------------------------------------------------------- ABORT ----


class AbortWatch:
    """results/<date>/ABORT (operator touch) -> write ABORT_REQUESTED once;
    the scheduler honors it at its next phase boundary. The watchdog itself
    never kills the scheduler — ABORT is strictly cooperative."""

    def __init__(self, results_dir, journal):
        d = Path(results_dir)
        self.abort_path = d / "ABORT"
        self.flag_path = d / "ABORT_REQUESTED"
        self.journal = journal
        self.done = False

    def poll(self, now_wall: float) -> bool:
        if self.done or not self.abort_path.exists():
            return False
        if not self.flag_path.exists():
            _atomic_write_json(self.flag_path, {
                "requested_at": _iso(now_wall), "source": "watchdog",
                "abort_file": str(self.abort_path)})
        self.journal.event(
            "abort_requested",
            note="cooperative wind-down requested; scheduler reads "
                 "ABORT_REQUESTED at its next phase boundary")
        self.done = True
        return True


# ------------------------------------------------------------- watchdog ----


class Watchdog:
    """Composes the monitors; one poll_once() per tick, run() loops it.
    Returns False from poll_once() (and exits run()) only after the final
    report is on disk: scheduler dead, or scheduler finished + journal
    merged. Every failure mode still leaves the user a report."""

    def __init__(self, results_dir, clock, sysctl=None, probe=None,
                 scheduler_pid=None, **overrides):
        self.cfg = dict(DEFAULT_CFG)
        self.cfg.update(overrides)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.sysctl = sysctl if sysctl is not None else \
            RealSys(self.cfg["console_socket"], self.cfg["serial_port"])
        self.hb_path = self.results_dir / "heartbeat.json"
        self.results_path = self.results_dir / "results.json"
        self.report_path = self.results_dir / "report.md"
        self.journal = Journal(self.results_dir, clock, self.sysctl)
        self.deadman = DeadMan(self.hb_path, scheduler_pid,
                               probe if probe is not None else default_pid_probe,
                               fresh_s=self.cfg["hb_fresh_s"],
                               grace_s=self.cfg["startup_grace_s"],
                               started_mono=clock.monotonic())
        self.bolty = ConsoleRecovery(self.sysctl, clock, self.journal, self.cfg)
        probe_fn = probe if probe is not None else default_pid_probe
        self.ccid = ReaderMonitor(self.sysctl, clock, self.journal, self.cfg,
                                  hb_path=self.hb_path, scheduler_pid=scheduler_pid,
                                  probe=probe_fn)
        self.abortw = AbortWatch(self.results_dir, self.journal)
        self.done_reason: str | None = None

    # -- per-tick ---------------------------------------------------------
    def poll_once(self) -> bool:
        now_m, now_w = self.clock.monotonic(), self.clock.time()
        self.abortw.poll(now_w)
        reasons = self.deadman.reasons(now_m, now_w)
        if reasons:
            state = self.journal.load_state()
            if self._scheduler_finished(state):
                self._finish_after_scheduler(state, now_w)
            else:
                self._handle_scheduler_dead(reasons, now_w)
            return False
        phase = (load_heartbeat(self.hb_path) or {}).get("phase") or "PREFLIGHT"
        mode_b = "Mode B" in str(
            (self.journal.load_state().get("mode_decision") or {}).get("mode", ""))
        window = self._window(phase, mode_b)
        if window == "bolty":
            self.ccid.reset()
            self.bolty.poll_if_due(now_m)
        elif window == "ccid":
            self.bolty.reset()
            self.ccid.poll_if_due(now_m)
        else:  # ROLE_GATE: the role switch itself drives the services
            self.bolty.reset()
            self.ccid.reset()
        return True

    @staticmethod
    def _window(phase: str, mode_b: bool) -> str:
        if phase == "ROLE_GATE":
            return "passive"
        if phase == "WINDOW2" and not mode_b:
            return "ccid"
        return "bolty"

    @staticmethod
    def _scheduler_finished(state: dict) -> bool:
        run = state.get("run") or {}
        return run.get("status") in FINISHED_STATUSES or \
            run.get("exit_code") is not None

    # -- terminal paths -----------------------------------------------------
    def _handle_scheduler_dead(self, reasons, now_wall: float) -> None:
        hb = load_heartbeat(self.hb_path)
        self.journal.anomaly("scheduler_dead", reasons=list(reasons),
                             scheduler_pid=self.deadman.pid,
                             hb_phase=(hb or {}).get("phase"))
        marker = self.results_dir / "PCSCD_RESTART_REQUEST"
        if marker.exists():
            self.journal.event("pcscd_restart_request_pending_at_death",
                               detail="marker left in place as evidence; the "
                                      "dead scheduler cannot honor it")
        state = self.journal.merge_sidecar(self.journal.load_state())
        run = state.setdefault("run", {})
        run["scheduler_died_at"] = _iso(now_wall)
        run["status"] = "scheduler died — partial report (watchdog)"
        run.setdefault("started_at", None)
        if not run.get("ended_at"):
            run["ended_at"] = _iso(now_wall)
        _atomic_write_json(self.results_path, state)
        self._write_report(state)
        self.done_reason = "scheduler_dead"

    def _finish_after_scheduler(self, state: dict, now_wall: float) -> None:
        state = self.journal.merge_sidecar(state)
        _atomic_write_json(self.results_path, state)
        self._write_report(state)
        self.done_reason = "scheduler_completed"

    def _write_report(self, state: dict) -> None:
        builder = _build_report_md or _fallback_report_md
        _atomic_write_text(self.report_path, builder(state))

    # -- main loop ----------------------------------------------------------
    def run(self) -> int:
        self.journal.event("watchdog_started", pid=os.getpid(),
                           scheduler_pid=self.deadman.pid,
                           results_dir=str(self.results_dir))
        while self.done_reason is None:
            self.poll_once()
            if self.done_reason is None:
                self.clock.sleep(self.cfg["poll_tick_s"])
        self.journal.event("watchdog_exit", reason=self.done_reason)
        return 0


def _fallback_report_md(state: dict) -> str:
    """Minimal builder used only when overnight.py is not importable (todo-5
    tolerant protocol). Same state shape, less decoration."""
    run = state.get("run", {})
    out = ["# Overnight HIL Audit Report",
           "",
           f"- Started: {run.get('started_at')}",
           f"- Ended: {run.get('ended_at')}",
           f"- Status: {run.get('status')} (exit_code={run.get('exit_code')})",
           f"- Scheduler died at: {run.get('scheduler_died_at')}",
           "",
           "_watchdog fallback builder (overnight.py import failed); full "
           "data: results.json + watchdog.jsonl._",
           "",
           "## Phases",
           ""]
    for p in state.get("phases", []):
        out.append(f"- {p.get('name')}: {p.get('status')} — "
                   f"{p.get('detail') or ''}")
    out += ["", "## Anomaly Timeline", ""]
    for e in state.get("timeline", []):
        if e.get("level") == "anomaly":
            extra = {k: v for k, v in e.items()
                     if k not in ("level", "kind", "ts")}
            out.append(f"- `{e.get('ts')}` **{e.get('kind')}** "
                       f"{json.dumps(extra, default=str)[:200]}")
    return "\n".join(out) + "\n"


# -------------------------------------------------------------- selftest ----


def run_selftest() -> bool:
    """Standalone `python3 watchdog.py --selftest`: drives the watchdog end
    to end against inline fakes (no hardware, no system calls) and checks the
    load-bearing invariants."""
    import tempfile

    results = []

    def check(name, ok):
        results.append(bool(ok))
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")

    class Clock:
        def __init__(self):
            self.m, self.w = 0.0, 1_800_000_000.0

        def monotonic(self):
            return self.m

        def time(self):
            return self.w

        def sleep(self, s):
            self.m += max(0.0, s)
            self.w += max(0.0, s)

    class Sys:
        def __init__(self):
            self.ping_ok, self.hb_age, self.gem, self.port = True, 5, True, True
            self.calls, self.signals = [], []

        def ping(self, socket_path=None, timeout=5.0):
            self.calls.append(("ping",))
            if self.ping_ok:
                return {"hb_age": self.hb_age, "lines": [], "error": None}
            return {"hb_age": None, "lines": [], "error": "refused"}

        def readers(self):
            self.calls.append(("readers",))
            rs = ["ACS ACR1252 1S ICC Reader 00 00"]
            if self.gem:
                rs.append("GemPCTwin serial 00 00")
            return rs

        def port_exists(self, port=None):
            self.calls.append(("port_exists",))
            return self.port

        def rts_pulse_reset(self, port=None):
            self.calls.append(("rts_pulse_reset",))

        def usb_rescan(self):
            self.calls.append(("usb_rescan",))

        def systemctl(self, *argv):
            self.calls.append(("systemctl",) + argv)

        def journalctl(self, units=("pcscd", "bolty-console"), n=50):
            self.calls.append(("journalctl",))
            return "snapshot\n"

        def cmd_kinds(self):
            return [c[0] for c in self.calls
                    if c[0] in ("systemctl", "rts_pulse_reset", "usb_rescan")]

    class Probe:
        def __init__(self):
            self.alive = True

        def __call__(self, pid):
            self.signals = getattr(self, "signals", []) + [(pid, 0)]
            return self.alive

    def hb_write(d, clock, phase="WINDOW1"):
        ts = datetime.fromtimestamp(clock.time(), tz=timezone.utc)
        (d / "heartbeat.json").write_text(json.dumps(
            {"pid": 4242, "ts": ts.isoformat(), "phase": phase}))

    def tick(dog, clock, d, advance=0.0, phase="WINDOW1"):
        clock.sleep(advance)
        hb_write(d, clock, phase)
        return dog.poll_once()

    tiny = dict(poll_tick_s=1.0, ping_poll_s=1.0, console_dead_s=3.0,
                hb_gap_s=60.0, readers_poll_s=1.0, reader_gone_s=3.0,
                daemon_settle_s=0.0, pcscd_settle_s=0.0)

    # 1. healthy night: no commands, no signals, no report
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock, sys_, probe = Clock(), Sys(), Probe()
        dog = Watchdog(d, clock, sysctl=sys_, probe=probe,
                       scheduler_pid=4242, **tiny)
        for _ in range(5):
            tick(dog, clock, d, advance=1)
        check("healthy run is quiet", not sys_.cmd_kinds()
              and dog.done_reason is None)

    # 2. recovery: order, never-reflash, cap-then-degrade. Each episode needs
    #    dead >= 3s (console_dead_s=3); after 2 recoveries the watchdog goes
    #    passive, so the pulse count freezes at exactly 2.
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock, sys_, probe = Clock(), Sys(), Probe()
        dog = Watchdog(d, clock, sysctl=sys_, probe=probe,
                       scheduler_pid=4242, **tiny)
        sys_.ping_ok = False
        for _ in range(30):
            tick(dog, clock, d, 1)
            if sys_.cmd_kinds().count("rts_pulse_reset") >= 2:
                break
        tick(dog, clock, d, 1)   # third episode: observe the failure again
        tick(dog, clock, d, 5)   # dead >= 3s -> degrade row, no third pulse
        flat = " ".join(" ".join(map(str, c)) for c in sys_.calls)
        check("never reflash", all(b not in flat for b in
                                   ("esptool", "write-flash", "write_flash")))
        check("recovery order stop->rts->start",
              sys_.cmd_kinds()[:3] == ["systemctl", "rts_pulse_reset",
                                       "systemctl"])
        check("no usb rescan while port present",
              "usb_rescan" not in sys_.cmd_kinds())
        check("recovery capped at 2",
              sys_.cmd_kinds().count("rts_pulse_reset") == 2)
        kinds = [json.loads(ln)["kind"] for ln in
                 (d / "watchdog.jsonl").read_text().splitlines()]
        check("passive degrade row", "recovery_degraded" in kinds)

    # 3. dead-man: partial report + scheduler_died_at
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock, sys_, probe = Clock(), Sys(), Probe()
        (d / "results.json").write_text(json.dumps({
            "run": {"started_at": "x", "ended_at": None, "exit_code": None,
                    "status": "running"},
            "phases": [], "rows": [{"lane": "selftest_row", "type": "cycle",
                                    "status": "PASS", "phase": "WINDOW1"}],
            "timeline": [], "mode_decision": None}))
        hb_write(d, clock)
        clock.sleep(121)  # heartbeat now stale
        probe.alive = False
        dog = Watchdog(d, clock, sysctl=sys_, probe=probe,
                       scheduler_pid=4242, **tiny)
        check("dead-man exits", dog.poll_once() is False)
        state = json.loads((d / "results.json").read_text())
        check("scheduler_died_at marked", bool(state["run"]["scheduler_died_at"]))
        md = (d / "report.md").read_text()
        check("report rendered", "scheduler died" in md and
              "selftest_row" in md)
        check("probes only, never kills",
              all(s[1] == 0 for s in probe.signals))

    # 4. ABORT: cooperative flag
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock, sys_, probe = Clock(), Sys(), Probe()
        dog = Watchdog(d, clock, sysctl=sys_, probe=probe,
                       scheduler_pid=4242, **tiny)
        hb_write(d, clock)
        (d / "ABORT").write_text("")
        dog.poll_once()
        flag = d / "ABORT_REQUESTED"
        check("abort flag written", flag.exists() and dog.done_reason is None)
        check("scheduler untouched", all(s[1] == 0 for s in probe.signals))

    # 5. pcscd marker protocol (round-2): alive scheduler -> request marker
    #    (never a direct restart); dead scheduler -> direct restart allowed;
    #    one shared restart cap of 3, then degraded rows
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock, sys_, probe = Clock(), Sys(), Probe()
        dog = Watchdog(d, clock, sysctl=sys_, probe=probe,
                       scheduler_pid=4242, **tiny)
        sys_.gem = False
        marker = d / "PCSCD_RESTART_REQUEST"
        tick(dog, clock, d, 0, phase="WINDOW2")
        tick(dog, clock, d, 4, phase="WINDOW2")  # gone >= 3s -> request
        check("pcscd marker requested, no direct restart",
              marker.exists() and
              not [c for c in sys_.calls if c[:2] == ("systemctl", "restart")])
        marker.unlink()  # scheduler restarted under its lock
        tick(dog, clock, d, 2, phase="WINDOW2")  # consumption observed (1/3)
        probe.alive = False  # scheduler dies mid-night
        for _ in range(2):  # dead-mode episodes -> direct restarts (2/3, 3/3)
            clock.sleep(4)
            dog.ccid.poll_if_due(clock.m)  # observe
            clock.sleep(4)
            dog.ccid.poll_if_due(clock.m)  # trigger: direct restart
        clock.sleep(4)
        dog.ccid.poll_if_due(clock.m)  # observe again
        clock.sleep(4)
        dog.ccid.poll_if_due(clock.m)  # cap reached -> degraded row only
        direct = [c for c in sys_.calls if c[:2] == ("systemctl", "restart")]
        kinds = [json.loads(ln)["kind"] for ln in
                 (d / "watchdog.jsonl").read_text().splitlines()]
        check("direct restarts only after scheduler death", len(direct) == 2)
        check("shared cap 3 across marker+direct", kinds.count("pcscd_restart")
              == 3 and "recovery_degraded" in kinds)

    ok = all(results)
    print(f"watchdog selftest: {'OK' if ok else 'FAILED'} "
          f"({sum(results)}/{len(results)} checks)")
    return ok


# ------------------------------------------------------------------- CLI ----


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Overnight watchdog + recovery playbook (todo 16). "
                    "Runs as an INDEPENDENT process next to overnight.py.")
    ap.add_argument("--config", help="results/<date>/config.json (the same "
                                     "file overnight.py reads)")
    ap.add_argument("--pid", type=int,
                    help="scheduler pid (default: config/ARMED.json/"
                         "heartbeat)")
    ap.add_argument("--results-dir", help="override the results directory")
    ap.add_argument("--selftest", action="store_true",
                    help="run the mocked built-in selftest and exit")
    args = ap.parse_args(argv)

    if args.selftest:
        return 0 if run_selftest() else 1
    if not args.config:
        print("error: --config is required for real runs (or use --selftest)",
              file=sys.stderr)
        return 2
    try:
        cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: cannot read config {args.config}: {e}", file=sys.stderr)
        return 2

    wd_cfg = dict(cfg.get("watchdog") or {})
    hb_cfg = cfg.get("hb") or {}
    if hb_cfg.get("console_socket"):
        wd_cfg.setdefault("console_socket", hb_cfg["console_socket"])
    if cfg.get("serial_port"):
        wd_cfg.setdefault("serial_port", cfg["serial_port"])
    results_dir = args.results_dir or cfg.get("results_dir") or \
        str(Path(args.config).resolve().parent)
    pid = resolve_scheduler_pid(args.pid, cfg, results_dir)

    dog = Watchdog(results_dir, RealClock(), scheduler_pid=pid, **wd_cfg)
    print(f"[watchdog] started: results_dir={results_dir} "
          f"scheduler_pid={pid}")
    rc = dog.run()
    print(f"[watchdog] exit: reason={dog.done_reason} "
          f"report={dog.report_path}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
