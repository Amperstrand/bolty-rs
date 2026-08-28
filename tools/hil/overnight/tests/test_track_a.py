#!/usr/bin/env python3
"""Tests for overnight Track A: burn-cycle driver + console fuzz + hw checks.

Pure-logic TDD suite (plan todo 7). No hardware, no real unix socket, no
network — the subprocess runner, console send/ping and clock are faked.

Component sink contract exercised here: every row/anomaly is ONE dict passed
to the sink; anomalies carry an "anomaly": "<kind>" key.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/overnight/tests/test_track_a.py -q
"""

import contextlib
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ledger  # noqa: E402
from ledger import CardSafetyHalt, Ledger  # noqa: E402

import track_a  # noqa: E402
from track_a import (  # noqa: E402
    EXPECTED_GATES,
    FORBIDDEN_PREFIXES,
    FUZZ_ALLOWLIST,
    MIN_CYCLE_GAP_S,
    FuzzGenerator,
    audit_line_start,
    diff_crashlog,
    parse_crashlog,
    parse_cycle_output,
)

UID_STICK = "04C474FA967380"
ISSUER = "00000000000000000000000000000001"


class FakeClock:
    def __init__(self):
        self._mono = 0.0

    def monotonic(self):
        return self._mono

    def time(self):
        return self._mono + 1_800_000_000.0

    def sleep(self, s):
        self._mono += max(0.0, s)


def make_ledger(tmp_path):
    return Ledger(tmp_path / "card_ledger.json", issuer_key=ISSUER)


# --------------------------------------------------------------- fixtures ----

CYCLE_ALL_PASS = """\
=== PING (daemon health) ===
alive hb_age=1s opened=123s ago
OK
=== uid (expect our card) ===
UID: 04C474FA967380
OK
=== stage + burn ===
url https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}
burn complete
OK
inspect: state=provisioned
OK
picc: sdm=ok uid_match=true
OK
TAP_URL: https://boltcardpoc.psbt.me/?p=AB91AEBF0123456789ABCDEF01234567&c=00112233
worker tap HTTP: 200
wipe complete
OK
inspect: state=blank
OK

===== CYCLE SUMMARY =====
  burn                   : PASS
  inspect_provisioned    : PASS
  picc_sdm_ok            : PASS
  worker_tap_200         : PASS
  wipe                   : PASS
  inspect_blank          : PASS
TAP_URL: https://boltcardpoc.psbt.me/?p=AB91AEBF0123456789ABCDEF01234567&c=00112233
RESULT: ALL PASS
"""

CYCLE_FAIL_VARIANT = """\
=== PING (daemon health) ===
alive hb_age=1s opened=123s ago
OK
=== uid (expect our card) ===
UID: 04C474FA967380
OK
=== stage + burn ===
burn complete
OK
inspect: state=provisioned
OK
picc: sdm=ok uid_match=true
OK
worker tap HTTP: 000
wipe complete
OK
inspect: state=blank
OK

===== CYCLE SUMMARY =====
  burn                   : PASS
  inspect_provisioned    : PASS
  picc_sdm_ok            : PASS
  worker_tap_200         : FAIL
  wipe                   : PASS
  inspect_blank          : PASS
TAP_URL: https://boltcardpoc.psbt.me/?p=AB91AEBF0123456789ABCDEF01234567&c=00112233
RESULT: FAILURES PRESENT
"""

CYCLE_UID_MISMATCH = """\
=== PING (daemon health) ===
alive hb_age=1s opened=123s ago
OK
=== uid (expect our card) ===
UID: 040C60FA967380
OK
FAIL: expected 04c474fa967380, got: UID: 040C60FA967380
"""


class FakeRunner:
    """Stands in for the burn_cycle.py subprocess call."""

    def __init__(self, outputs, duration_s=0.0, clock=None):
        self.outputs = list(outputs)
        self.calls = []
        self.duration_s = duration_s
        self.clock = clock

    def __call__(self, argv, env, timeout, cwd):
        self.calls.append({"t": self.clock.monotonic() if self.clock else None,
                           "argv": list(argv), "env": dict(env),
                           "timeout": timeout, "cwd": str(cwd)})
        if self.clock:
            self.clock.sleep(self.duration_s)
        rc, out = self.outputs.pop(0)
        return rc, out, ""


# ----------------------------------------------------- fuzz allowlist audit ----

def test_fuzz_allowlist_exactly_documented():
    assert set(FUZZ_ALLOWLIST) == {
        "help", "ver", "status", "uid", "i2cscan", "hwinfo", "crashlog", "derivekeys",
    }


def test_allowlist_no_forbidden_overlap():
    # construction safety: no allowlisted token may collide with a forbidden
    # prefix in either direction, so picking from the allowlist can never
    # emit a card-auth or mutating command.
    for a in FUZZ_ALLOWLIST:
        for p in FORBIDDEN_PREFIXES:
            assert not a.startswith(p), (a, p)
            assert not (p.startswith(a) and a != p), (a, p)


def test_audit_line_start_rejects_forbidden_and_accepts_safe():
    for bad in (b"burn", b"wipe now", b"keys 1111", b"ota http://x",
                b"reset", b"button-mode", b"provision-ota-key", b"auth",
                b"INSPECT", b"picc", b"wifi 2 pass", b"token abc",
                b"   burn", b"\twipe", b"\x0bburn", b"\xa0wipe", b"\x1cburn",
                b"\x85ota", b"\x1fkeys"):  # daemon strips the full isspace set
        assert not audit_line_start(bad), bad
    for good in (b"help", b"ver", b"status x", b"uid", b"i2cscan",
                 b"hwinfo", b"crashlog", b"derivekeys --uid 04",
                 b"\x00\x03\x15", b"\x7f garbage \xff", b"123 not-a-cmd",
                 b"", b"   ", b"--flag=x"):
        assert audit_line_start(good), good


def test_fuzz_10k_sample_zero_forbidden_at_line_start():
    gen = FuzzGenerator(seed=20260828)
    lines = gen.generate(10_000)
    assert len(lines) == 10_000
    for line in lines:
        # CR/LF exclusion proof: with the invariant held, splitting on [\r\n]
        # yields exactly ONE segment per line (zero device-side line breaks
        # the generator did not choose) and every segment start is clean.
        segments = re.split(r"[\r\n]+", line.decode("latin1", "replace"))
        assert len(segments) == 1, repr(line[:40])
        low = segments[0].lstrip(" \t\n\r\v\f\x1c\x1d\x1e\x1f\x85\xa0").lower()
        for p in FORBIDDEN_PREFIXES:
            assert not low.startswith(p), (p, line[:40])
        assert audit_line_start(line), line[:40]


def test_fuzz_corpus_shapes_and_determinism():
    gen = FuzzGenerator(seed=7)
    lines = gen.generate(4_000)
    joined = b"".join(lines)
    for byte in (0x00, 0x03, 0x15):  # framing-relevant control bytes present
        assert bytes([byte]) in joined, hex(byte)
    assert b"\r" not in joined and b"\n" not in joined  # round-2 invariant
    assert any(len(ln) >= 4096 for ln in lines)  # 4KB lines exist
    allow = {w.encode() for w in FUZZ_ALLOWLIST}
    assert any(ln.split(b" ", 1)[0].lower() in allow
               for ln in lines if b" " in ln)  # allowlisted lines with args
    assert FuzzGenerator(seed=7).generate(100) == lines[:100]  # deterministic


# --------------------------------------------------------- gate parsing ----

def test_gate_parser_six_pass():
    parsed = parse_cycle_output(CYCLE_ALL_PASS)
    assert tuple(parsed["gates"]) == EXPECTED_GATES
    assert all(v == "PASS" for v in parsed["gates"].values())
    assert parsed["missing_gates"] == []
    assert parsed["ok"] is True
    assert parsed["result_line"] == "RESULT: ALL PASS"
    assert parsed["tap_url"].startswith("https://boltcardpoc.psbt.me/?p=")


def test_gate_parser_fail_variant():
    parsed = parse_cycle_output(CYCLE_FAIL_VARIANT)
    assert parsed["gates"]["worker_tap_200"] == "FAIL"
    assert parsed["gates"]["burn"] == "PASS"
    assert parsed["ok"] is False
    assert parsed["result_line"] == "RESULT: FAILURES PRESENT"
    assert parsed["missing_gates"] == []


def test_gate_parser_robust_to_garbage_and_missing_gates():
    parsed = parse_cycle_output("random boot noise\nno summary here")
    assert parsed["ok"] is False
    assert set(parsed["missing_gates"]) == set(EXPECTED_GATES)
    assert parse_cycle_output("")["ok"] is False
    assert parse_cycle_output(None)["ok"] is False


def test_driver_parses_early_exit_uid_mismatch():
    clock = FakeClock()
    runner = FakeRunner([(2, CYCLE_UID_MISMATCH)], clock=clock)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock)
    row = drv.run_cycle()
    assert row["status"] == "FAIL"
    assert row["rc"] == 2
    assert row["ok"] is False
    assert "expected" in row["raw_tail"]
    assert row["missing_gates"] == list(EXPECTED_GATES)


# ---------------------------------------------------- driver + ledger hook ----

def test_cycle_env_and_argv():
    clock = FakeClock()
    runner = FakeRunner([(0, CYCLE_ALL_PASS)], clock=clock)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock)
    drv.run_cycle()
    call = runner.calls[0]
    assert call["env"]["HIL_UID"].lower() == UID_STICK.lower()
    assert "--issuer" in call["argv"]
    assert call["argv"][call["argv"].index("--issuer") + 1] == ISSUER
    assert any(str(a).endswith("tools/hil/burn_cycle.py") for a in call["argv"])
    assert call["timeout"] > 0


def test_cycle_auth_fail_feeds_ledger(tmp_path):
    clock = FakeClock()
    out = CYCLE_FAIL_VARIANT.replace(
        "=== stage + burn ===",
        "=== stage + burn ===\nerror: card rejected auth: 91AE").replace(
        "  burn                   : PASS",
        "  burn                   : FAIL")
    runner = FakeRunner([(1, out)], clock=clock)
    led = make_ledger(tmp_path)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock, ledger_inst=led)
    row = drv.run_cycle()
    assert row["classification"] == "auth_fail"
    assert row["status"] == "FAIL"
    ctr = led.counters(UID_STICK)
    assert ctr["total_failures"] == 1
    assert ctr["consecutive_failures"] == 1


def test_cycle_plain_fail_ledger_untouched(tmp_path):
    clock = FakeClock()
    runner = FakeRunner([(1, CYCLE_FAIL_VARIANT)], clock=clock)
    led = make_ledger(tmp_path)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock, ledger_inst=led)
    drv.run_cycle()
    ctr = led.counters(UID_STICK)
    assert ctr["total_failures"] == 0
    assert ctr["auth_attempts"] == 0
    assert ctr["ops_by_type"].get("burn_cycle") == 1  # op counted, failures not


def test_ledger_halt_stops_cycles_before_start(tmp_path):
    clock = FakeClock()
    runner = FakeRunner([(0, CYCLE_ALL_PASS)], clock=clock)
    led = make_ledger(tmp_path)
    for _ in range(ledger.DEFAULT_CONSECUTIVE_LIMIT):
        led.record_auth_failure(UID_STICK)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock, ledger_inst=led)
    with pytest.raises(CardSafetyHalt):
        drv.run_cycle()
    assert runner.calls == []  # never reached the subprocess


def test_driver_timeout_records_fail_and_continues():
    clock = FakeClock()

    class TimingOutRunner(FakeRunner):
        def __call__(self, argv, env, timeout, cwd):
            raise subprocess.TimeoutExpired(cmd="burn_cycle.py", timeout=timeout)

    runner = TimingOutRunner([(0, CYCLE_ALL_PASS)], clock=clock)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock)
    row = drv.run_cycle()
    assert row["status"] == "FAIL"
    assert row["ok"] is False
    assert row["rc"] is None
    assert "timeout" in row["raw_tail"].lower()


def test_driver_kills_subprocess_on_lane_stop(tmp_path):
    # real local subprocess (sleep), no hardware: the lane-stop runner must
    # kill it within a poll slice instead of blocking for the full timeout
    script = tmp_path / "fake_cycle.py"
    script.write_text("import time; time.sleep(30)\n")
    drv = track_a.BurnCycleDriver(
        burn_cycle_path=script, issuer=ISSUER, uid=UID_STICK,
        cycle_timeout_s=25.0, should_stop=lambda: True)
    t0 = time.monotonic()
    row = drv.run_cycle()
    elapsed = time.monotonic() - t0
    assert elapsed < 10.0, elapsed
    assert row["status"] == "FAIL"
    assert "stopped" in row["raw_tail"]


# ------------------------------------------------ pacing / time budget ----

def test_pacing_min_30s_between_cycle_starts():
    clock = FakeClock()
    runner = FakeRunner([(0, CYCLE_ALL_PASS)] * 3, duration_s=5.0, clock=clock)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock)
    rows = drv.run_cycles(max_cycles=3)
    assert len(rows) == 3
    starts = [c["t"] for c in runner.calls]
    assert starts[0] == 0.0
    for a, b in zip(starts, starts[1:]):
        assert b - a >= MIN_CYCLE_GAP_S - 1e-9
    assert MIN_CYCLE_GAP_S == 30.0


def test_budget_stops_at_deadline():
    clock = FakeClock()
    runner = FakeRunner([(0, CYCLE_ALL_PASS)] * 99, duration_s=10.0, clock=clock)
    drv = track_a.BurnCycleDriver(runner=runner, issuer=ISSUER, uid=UID_STICK,
                                  clock=clock, min_cycle_gap_s=0.0)
    rows = drv.run_cycles(deadline=35.0, min_remaining_s=10.0)
    # cycles start at t=0,10,20; at t=30 the remaining 5s < 10s min -> stop
    assert [c["t"] for c in runner.calls] == [0.0, 10.0, 20.0]
    assert len(rows) == 3


# ------------------------------------------------------------- crashlog ----

def test_crashlog_parse():
    text = ("[CRASHLOG]\n"
            "  Boot count: 7\n"
            "  This boot reason: POWERON\n"
            "  Last crash: TASK_WDT on boot #5\n"
            "[CRASHLOG] END\n")
    p = parse_crashlog(text)
    assert p["boot_count"] == 7
    assert p["boot_reason"] == "POWERON"
    assert p["last_crash"] == "TASK_WDT"
    assert p["last_crash_boot"] == 5

    none = parse_crashlog("[CRASHLOG]\n  Boot count: 1\n"
                          "  This boot reason: POWERON\n  Last crash: none\n"
                          "[CRASHLOG] END\n")
    assert none["last_crash"] is None
    assert parse_crashlog("noise")["boot_count"] is None  # never raises


def _cl(boot, reason="POWERON", crash=None, crash_boot=None):
    return {"boot_count": boot, "boot_reason": reason, "last_crash": crash,
            "last_crash_boot": crash_boot}


def test_crashlog_baseline_then_same_no_anomaly():
    first = diff_crashlog(None, _cl(7))
    assert first["anomaly"] is False and first["first"] is True
    again = diff_crashlog(_cl(7), _cl(7))
    assert again["anomaly"] is False and again["rebooted"] is False


def test_crashlog_epoch_reset_not_anomaly():
    # reflash wipes NVS -> boot count resets; diff must baseline, not alarm
    d = diff_crashlog(_cl(200), _cl(1))
    assert d["epoch_changed"] is True
    assert d["anomaly"] is False


def test_crashlog_abnormal_reboot_is_anomaly():
    d = diff_crashlog(_cl(7), _cl(8, reason="PANIC", crash="PANIC", crash_boot=7))
    assert d["rebooted"] is True
    assert d["abnormal_reboot"] is True
    assert d["new_crash"] is True
    assert d["anomaly"] is True


def test_crashlog_new_crash_same_bootcount_is_anomaly():
    d = diff_crashlog(_cl(7), _cl(7, crash="BROWNOUT", crash_boot=6))
    assert d["rebooted"] is False
    assert d["new_crash"] is True
    assert d["anomaly"] is True


def test_crashlog_normal_reboot_not_anomaly():
    d = diff_crashlog(_cl(7), _cl(8, reason="POWERON"))
    assert d["rebooted"] is True
    assert d["abnormal_reboot"] is False
    assert d["anomaly"] is False


def test_hwchecker_run_once_rows_and_crashlog_anomaly():
    checks = {
        "hwinfo": "battery 4100 mV\nOK 2 lines",
        "i2cscan": "0x28\nOK 1 lines",
        "status": "state=idle nfc=ok\nOK 1 lines",
    }
    crashlog_1 = "[CRASHLOG]\n  Boot count: 7\n  This boot reason: POWERON\n" \
                 "  Last crash: none\n[CRASHLOG] END\nOK 4 lines"
    crashlog_2 = "[CRASHLOG]\n  Boot count: 8\n  This boot reason: TASK_WDT\n" \
                 "  Last crash: TASK_WDT on boot #7\n[CRASHLOG] END\nOK 4 lines"
    responses = iter([checks["hwinfo"], checks["i2cscan"], checks["status"],
                      crashlog_1, checks["hwinfo"], checks["i2cscan"],
                      checks["status"], crashlog_2])

    def console(cmd):
        assert cmd in ("hwinfo", "i2cscan", "status", "crashlog")
        return next(responses)

    rows, anomalies = [], []

    def sink(ev):
        (anomalies if "anomaly" in ev else rows).append(ev)

    hw = track_a.HwChecker(console_fn=console, sink=sink)
    hw.run_once()
    kinds = [r.get("cmd") for r in rows]
    assert kinds == ["hwinfo", "i2cscan", "status", "crashlog"]
    assert not anomalies
    hw.run_once()
    assert anomalies and anomalies[0]["anomaly"] == "abnormal_reset"


# --------------------------------------------------------- fuzz driver ----

class FakeConsole:
    def __init__(self, ping_script):
        self.sent = []
        self.ping_script = list(ping_script)
        self.pings = 0

    def send(self, payload):
        self.sent.append(payload)
        return "OK 0 lines"

    def ping(self):
        self.pings += 1
        return self.ping_script.pop(0)


OK_PING = {"hb_age": 2,
           "lines": ["alive hb_age=2s opened=100s ago",
                     "[HB] alive t=100ms nfc=ok"], "error": None}
STALE_PING = {"hb_age": 900, "lines": ["alive hb_age=900s opened=1s ago"],
              "error": None}


def test_fuzzer_liveness_every_25_inputs():
    fc = FakeConsole([OK_PING] * 10)
    fuzzer = track_a.ConsoleFuzzer(send=fc.send, ping=fc.ping, clock=FakeClock(),
                                   liveness_every=25, hb_max_wait_s=60.0)
    stats = fuzzer.run(max_inputs=50)
    assert stats["inputs"] == 50
    assert stats["liveness_checks"] == 2
    assert stats["liveness_failures"] == 0
    assert fc.pings == 2


def test_fuzzer_hb_timeout_records_anomaly_and_stops():
    anomalies = []

    def sink(ev):
        if "anomaly" in ev:
            anomalies.append(ev)

    fc = FakeConsole([STALE_PING] * 100)
    fuzzer = track_a.ConsoleFuzzer(send=fc.send, ping=fc.ping, sink=sink,
                                   clock=FakeClock(), liveness_every=5,
                                   hb_max_wait_s=60.0, poll_s=10.0)
    stats = fuzzer.run(max_inputs=100)
    assert stats["inputs"] == 5  # stopped at the first liveness check
    assert stats["liveness_failures"] == 1
    assert anomalies and anomalies[0]["anomaly"] == "fuzz_liveness_failed"
    # strict mode (dry) turns the same evidence into a hard failure
    fc2 = FakeConsole([STALE_PING] * 100)
    fuzzer2 = track_a.ConsoleFuzzer(send=fc2.send, ping=fc2.ping, sink=sink,
                                    clock=FakeClock(), liveness_every=5,
                                    hb_max_wait_s=60.0, poll_s=10.0)
    with pytest.raises(track_a.LivenessError):
        fuzzer2.run(max_inputs=100, strict=True)


def test_fuzzer_offline_transport_is_soft():
    def broken_send(payload):
        raise OSError(2, "No such file or directory")

    anomalies = []

    def sink(ev):
        if "anomaly" in ev:
            anomalies.append(ev)

    fuzzer = track_a.ConsoleFuzzer(send=broken_send, ping=lambda: {},
                                   sink=sink, clock=FakeClock())
    stats = fuzzer.run(max_inputs=100)  # must NOT raise offline
    assert stats["inputs"] == 0
    assert anomalies and anomalies[0]["anomaly"] == "fuzz_console_offline"


def test_fuzzer_classifies_auth_fail_response(tmp_path):
    def evil_send(payload):
        return "error: authentication failed 91AE\nOK 1 lines"

    led = make_ledger(tmp_path)
    anomalies = []

    def sink(ev):
        if "anomaly" in ev:
            anomalies.append(ev)

    fuzzer = track_a.ConsoleFuzzer(send=evil_send, ping=lambda: OK_PING,
                                   sink=sink, clock=FakeClock(),
                                   ledger_inst=led, card_uid=UID_STICK)
    stats = fuzzer.run(max_inputs=30)
    assert stats["auth_fail_responses"] >= 1
    assert led.counters(UID_STICK)["total_failures"] >= 1
    assert anomalies


# --------------------------------------------------------- lane wiring ----

class StubCtx:
    """Duck-typed todo-5 PhaseContext (documented protocol members only)."""

    def __init__(self, running=lambda: True, cards=("stick",), fail_card=False):
        self.name, self.cards, self.pace_s = "stub", tuple(cards), 0.0
        self.dry_run, self.ledger = True, ledger
        self._running, self._fail_card = running, fail_card
        self.rows, self.skips, self.anomalies, self.sleep_total = [], [], [], 0.0

    def running(self):
        return self._running()

    def paused(self):
        return False

    def sleep(self, s):
        self.sleep_total += s

    @contextlib.contextmanager
    def card(self, card_id):
        if self._fail_card:
            raise track_a.MutationWindowClosed(card_id, "stub drain")
        yield card_id

    def row(self, **fields):
        self.rows.append(fields)
        return fields

    def skip(self, reason, **fields):
        self.skips.append((reason, fields))
        return fields

    def anomaly(self, kind, **fields):
        self.anomalies.append({"anomaly": kind, **fields})
        return fields

    def event(self, kind, **fields):
        return fields


def _stage_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HIL_UID_STICK", UID_STICK)
    monkeypatch.setenv("HIL_ISSUER", ISSUER)
    monkeypatch.setenv("OVERNIGHT_LEDGER_PATH", str(tmp_path / "card_ledger.json"))


def test_cycles_lane_rows_and_exit(tmp_path, monkeypatch):
    _stage_env(monkeypatch, tmp_path)

    class StubDriver:
        def __init__(self, sink=None, **kw):
            self.sink = sink or (lambda ev: None)

        def run_cycles(self, *, running, sleep=None, hold_card=None, **kw):
            n = 0
            while running() and n < 2:
                if hold_card is not None:
                    with hold_card():
                        self.sink({"type": "cycle", "status": "PASS", "cycle": n})
                else:
                    self.sink({"type": "cycle", "status": "PASS", "cycle": n})
                n += 1
            return []

    monkeypatch.setattr(track_a, "BurnCycleDriver", StubDriver)
    ctx = StubCtx()
    track_a.cycles_lane(ctx)
    cycles = [r for r in ctx.rows if r.get("type") == "cycle"]
    assert len(cycles) == 2


def test_cycles_lane_requires_staged_uid(tmp_path, monkeypatch):
    monkeypatch.delenv("HIL_UID_STICK", raising=False)
    monkeypatch.delenv("HIL_UID", raising=False)
    ctx = StubCtx()
    track_a.cycles_lane(ctx)
    assert ctx.rows == []
    assert ctx.skips and "HIL_UID_STICK" in ctx.skips[0][0]


def test_cycles_lane_honors_mutation_window_closed(tmp_path, monkeypatch):
    _stage_env(monkeypatch, tmp_path)

    class CardRaisingDriver:
        def __init__(self, **kw):
            pass

        def run_cycles(self, *, hold_card=None, **kw):
            with hold_card():
                pass
            return []

    monkeypatch.setattr(track_a, "BurnCycleDriver", CardRaisingDriver)
    ctx = StubCtx(fail_card=True)
    track_a.cycles_lane(ctx)
    assert ctx.skips and "mutation window" in ctx.skips[0][0]
    assert ctx.rows == []


def test_cycles_lane_card_safety_halt_halts_lane(tmp_path, monkeypatch):
    _stage_env(monkeypatch, tmp_path)

    class HaltingDriver:
        def __init__(self, **kw):
            pass

        def run_cycles(self, **kw):
            raise CardSafetyHalt(UID_STICK, "consecutive_limit")

    monkeypatch.setattr(track_a, "BurnCycleDriver", HaltingDriver)
    ctx = StubCtx()
    track_a.cycles_lane(ctx)
    assert any(a["anomaly"] == "card_safety_halt" for a in ctx.anomalies)


def test_register_and_build_lane():
    class FakeOrch:
        def __init__(self):
            self.specs = []

    orch = FakeOrch()
    specs = track_a.register(orch)
    assert len(orch.specs) == 3
    by = {s.name: s for s in specs}
    assert set(by) == {"track_a_cycles", "track_a_console_fuzz", "track_a_hwchecks"}
    for s in specs:
        assert s.window == "window1"
        assert callable(s.target)
    assert by["track_a_cycles"].cards == ("stick",)
    primary = track_a.build_lane()
    assert primary.name == "track_a_cycles"  # overnight.load_track_specs contract


def test_env_file_loader(tmp_path):
    envf = tmp_path / "overnight.env"
    envf.write_text("# comment\nHIL_ISSUER=abc123\nHIL_UID_STICK=\n"
                    "CONSECUTIVE_LIMIT=10\n")
    data = track_a.load_env_file(envf)
    assert data["HIL_ISSUER"] == "abc123"
    assert data["HIL_UID_STICK"] == ""
    assert "comment" not in data
    assert track_a.load_env_file(tmp_path / "missing.env") == {}


# ------------------------------------------------------------- selftest ----

def test_selftest_runs_offline_and_exits_zero(capsys):
    assert track_a.main(["--selftest"]) == 0
    out = capsys.readouterr().out
    assert "SELFTEST PASS" in out
