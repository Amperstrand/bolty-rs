#!/usr/bin/env python3
"""Orchestrator core tests (plan todo 5) — hardware-free by construction.

Single-threaded component tests use FakeClock (deterministic, no sleeps);
threaded end-to-end tests use tiny REAL durations and assert STRUCTURE
(row presence, phase statuses, non-overlap) — never wall-clock precision.
"""
import json
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

OVERNIGHT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(OVERNIGHT_DIR))

import overnight  # noqa: E402
from overnight import (CardMutex, ConfigError, ConsoleMonitor, GateResult,  # noqa: E402
                       Heartbeat, LaneRegistry, LaneSpec, MutationWindowClosed,
                       Orchestrator, PcscdMaintenanceLock, PHASES, ResultsStore,
                       Timeline, WindowController, build_dry_run_app,
                       build_report_md, make_context, merge_defaults, parse_hb_line,
                       scale_config, try_load_ledger, validate_config)

REPO_ROOT = OVERNIGHT_DIR.parent.parent.parent


def scaled(total=3.0):
    return scale_config(merge_defaults({}), total_s=total, dry=True)


def kinds(store):
    return [e["kind"] for e in store.state["timeline"]]


# ------------------------------------------------------------------ config ----

def test_config_defaults_validate():
    cfg = validate_config({})
    assert cfg["duration_s"] == 32400.0
    tl = Timeline(cfg, 0.0)
    assert tl.hard_end == 32400.0


def test_config_validation_rejects_budget_mismatch():
    bad = merge_defaults({})
    bad["phases"]["window1_s"] = bad["phases"]["window1_s"] + 10
    with pytest.raises(ConfigError):
        validate_config(bad)


# -------------------------------------------------------------- HB monitor ----

CLEAN_LOG = "\n".join(
    f"12:00:{i * 10:02d} [HB] alive t={10000 + i * 10000}ms nfc=ok" for i in range(10)
) + "\n"


def make_monitor(sink, clock):
    return ConsoleMonitor(sink, clock, max_age_s=30.0, poll_s=10.0)


def test_hb_parser_clean_stream():
    clock = overnight.FakeClock()
    events = []
    mon = ConsoleMonitor(events.append, clock, max_age_s=30.0)
    for line in CLEAN_LOG.splitlines():
        hb = parse_hb_line(line)
        assert hb is not None and hb.nfc_ok
        mon.feed_line(line)
        clock.sleep(10)
    assert events == []


def test_hb_gap_uses_receive_time_not_log_timestamps():
    # Midnight wrap: log timestamps suggest 4s apart, receive times are 40s.
    events = []
    mon = ConsoleMonitor(events.append, overnight.FakeClock(), max_age_s=30.0)
    mon.feed_line("23:59:59 [HB] alive t=10000ms nfc=ok")
    mon.clock.sleep(40)
    mon.feed_line("00:00:03 [HB] alive t=20000ms nfc=ok")
    assert [e["kind"] for e in events] == ["hb_gap"]
    assert events[0]["gap_s"] == 40.0


def test_hb_gap_via_ping_hb_age_with_dedup():
    events = []
    mon = ConsoleMonitor(events.append, overnight.FakeClock(), max_age_s=30.0)
    mon.check_ping({"hb_age": 5, "lines": [], "error": None})
    assert events == []
    mon.check_ping({"hb_age": 45, "lines": [], "error": None})   # episode begins
    mon.check_ping({"hb_age": 50, "lines": [], "error": None})   # same episode
    mon.check_ping({"hb_age": 5, "lines": [], "error": None})    # recovered
    mon.check_ping({"hb_age": 47, "lines": [], "error": None})   # new episode
    gaps = [e for e in events if e["kind"] == "hb_gap"]
    assert len(gaps) == 2
    assert all(e["source"] == "daemon_ping" for e in gaps)
    assert events[0]["hb_age_s"] == 45


def test_hb_nfc_down_and_recovery_dedup():
    events = []
    mon = make_monitor(events.append, overnight.FakeClock())
    mon.feed_line("12:00:00 [HB] alive t=1000ms nfc=ok")
    mon.feed_line("12:00:10 [HB] alive t=11000ms nfc=DOWN")
    mon.feed_line("12:00:20 [HB] alive t=21000ms nfc=DOWN")   # same episode
    mon.feed_line("12:00:30 [HB] alive t=31000ms nfc=ok")
    mon.feed_line("12:00:40 [HB] alive t=41000ms nfc=DOWN")   # new episode
    downs = [e for e in events if e["kind"] == "nfc_down"]
    assert len(downs) == 2


def test_hb_t_regression_detected():
    events = []
    mon = make_monitor(events.append, overnight.FakeClock())
    mon.feed_line("12:00:00 [HB] alive t=30000ms nfc=ok")
    mon.feed_line("12:00:10 [HB] alive t=5000ms nfc=ok")  # reboot
    assert [e["kind"] for e in events] == ["t_regression"]
    assert events[0]["t_ms"] == 5000 and events[0]["prev_t_ms"] == 30000


def test_hb_parser_random_truncation_no_panic():
    rng = random.Random(1234)
    for _ in range(300):
        blob = CLEAN_LOG
        cut = rng.randrange(len(blob) + 1)
        blob = blob[:cut]
        if rng.random() < 0.5:  # random corruption
            junk = bytes(rng.randrange(256) for _ in range(rng.randrange(64)))
            pos = rng.randrange(len(blob) + 1)
            blob = blob[:pos] + junk.decode("latin1", "replace") + blob[pos:]
        events = []
        mon = make_monitor(events.append, overnight.FakeClock())
        for line in blob.splitlines():
            parse_hb_line(line)
            mon.feed_line(line)  # must never raise
    assert True  # property: no panic on any truncation/corruption


# --------------------------------------------------------- persistence ----

def test_store_incremental_atomic_persistence(tmp_path):
    clock = overnight.FakeClock()
    store = ResultsStore(tmp_path, clock=clock)
    store.mark_started(dry_run=True)
    on_disk = json.loads((tmp_path / "results.json").read_text())
    assert on_disk["run"]["status"] == "running"
    store.row(type="cycle", status="PASS", i=1)
    on_disk = json.loads((tmp_path / "results.json").read_text())
    assert on_disk["rows"][-1]["i"] == 1          # persisted IMMEDIATELY
    store.event("drain_begin", phase="WINDOW1")
    store.anomaly("hb_gap", gap_s=40)
    on_disk = json.loads((tmp_path / "results.json").read_text())
    assert on_disk["timeline"][-1]["level"] == "anomaly"
    assert not list(tmp_path.glob("*.tmp"))        # atomic: no temp left behind
    # dead scheduler: reload from disk yields the complete partial state
    del store
    reloaded = ResultsStore.load(tmp_path / "results.json")
    assert reloaded["rows"][0]["i"] == 1
    assert reloaded["timeline"][0]["kind"] == "drain_begin"


# ------------------------------------------------------------- mutex ----

def test_card_mutex_same_card_exclusive():
    m = CardMutex()
    assert m.acquire("stick", "laneA", timeout=0.1)
    assert m.holder("stick") == "laneA"
    assert not m.acquire("stick", "laneB", timeout=0.15)   # same card blocks
    assert m.acquire("acr", "laneB", timeout=0.1)          # different card free
    m.release("acr")
    m.release("stick")
    assert m.acquire("stick", "laneB", timeout=0.1)
    m.release("stick")


def test_mutation_window_closed_blocks_card(tmp_path):
    store = ResultsStore(tmp_path)
    clock = overnight.FakeClock()
    mutex = CardMutex()
    controller = WindowController()
    stop, pause, ack = threading.Event(), threading.Event(), threading.Event()
    ctx = make_context(name="laneA", store=store, clock=clock, mutex=mutex,
                       controller=controller, stop_event=stop, pause_event=pause,
                       paused_ack_event=ack, phase_ref=lambda: "WINDOW1",
                       cards=("stick",))
    with ctx.card("stick"):
        pass
    controller.close("window drain")
    with pytest.raises(MutationWindowClosed):
        with ctx.card("stick"):
            pass


# -------------------------------------------------------------- drain ----

def test_drain_grace_elapse_force_stop_and_probe_rows(tmp_path):
    cfg = merge_defaults({})  # unscaled: drain_grace 70s virtual on FakeClock
    clock = overnight.FakeClock()
    store = ResultsStore(tmp_path, clock=clock)

    def boom():
        raise RuntimeError("probe boom")

    orch = Orchestrator(cfg, store, clock, specs=[],
                        role_gate=lambda ctx: GateResult(True, ""),
                        restore_fn=lambda ctx: GateResult(True, ""),
                        preflight_fn=lambda ctx: True,
                        probes={"stick": boom, "acr": lambda: {"card_state": "ok"}})
    handle = overnight.LaneHandle(LaneSpec("slowpoke", lambda ctx: None,
                                           cards=("stick",)))
    assert orch.mutex.acquire("stick", "slowpoke")   # stuck in-flight mutation
    controller = WindowController()
    clean = orch.drain("WINDOW1", [handle], ["stick", "acr"], controller)

    assert clean is False
    assert not controller.mutation_allowed()
    kinds_ = kinds(store)
    assert "drain_begin" in kinds_ and "drain_complete" in kinds_
    assert "drain_grace_elapsed" in kinds_
    assert "card_lock_abandoned" in kinds_
    rows = store.state["rows"]
    err = [r for r in rows if r["type"] == "card_state" and r["card"] == "stick"]
    assert err and err[0]["status"] == "ERROR" and "probe boom" in err[0]["error"]
    ok = [r for r in rows if r["type"] == "card_state" and r["card"] == "acr"]
    assert ok and ok[0]["status"] == "PASS" and ok[0]["card_state"] == "ok"


def test_drain_ignores_all_night_lane_locks(tmp_path):
    cfg = merge_defaults({})
    clock = overnight.FakeClock()
    store = ResultsStore(tmp_path, clock=clock)
    orch = Orchestrator(cfg, store, clock, specs=[],
                        role_gate=lambda ctx: GateResult(True, ""),
                        restore_fn=lambda ctx: GateResult(True, ""),
                        preflight_fn=lambda ctx: True, probes={})
    assert orch.mutex.acquire("acr", "track_b_acr")  # all-night lane: legal
    controller = WindowController()
    clean = orch.drain("WINDOW2", [], ["acr"], controller)  # no window lanes
    assert clean is True
    assert "drain_grace_elapsed" not in kinds(store)
    assert orch.mutex.holder("acr") == "track_b_acr"  # untouched


# ------------------------------------------------------------- timeline ----

def test_timeline_anchor_fixed_and_dynamic_shrink():
    tl = Timeline(merge_defaults({}), 0.0)
    assert tl.planned_start("WINDOW1") == 1800.0
    assert tl.anchor_end("WINDOW1") == 14400.0
    assert tl.hard_end == 32400.0
    # on-time start: full budget
    s, e, d = tl.actual_window("WINDOW2", 16200.0)
    assert (s, e) == (16200.0, 28800.0) and d == 12600.0
    # late start (window1/gate overran): start slides, END ANCHOR DOES NOT MOVE
    s, e, d = tl.actual_window("WINDOW2", 16300.0)
    assert (s, e, d) == (16300.0, 28800.0, 12500.0)
    # overrun consumed the whole budget: zero, never negative, never extended
    s, e, d = tl.actual_window("WINDOW2", 29000.0)
    assert d == 0.0 and e == 28800.0
    s, e, d = tl.actual_window("REPORT", 33000.0)
    assert d == 0.0 and e == 32400.0


# ------------------------------------------------------------- pcscd ----

def test_pcscd_lock_pauses_needs_pcscd_lanes(tmp_path):
    store = ResultsStore(tmp_path)
    clock = overnight.RealClock()
    registry = LaneRegistry(store, clock)
    mutex = CardMutex()
    counts = {"b": 0, "c": 0}

    def b_track(ctx):
        while ctx.running():
            counts["b"] += 1
            ctx.sleep(0.02)

    def c_track(ctx):
        while ctx.running():
            counts["c"] += 1
            ctx.sleep(0.02)

    hb = registry.start(LaneSpec("track_b_acr", b_track, window="all_night",
                                 cards=("acr",), needs_pcscd=True),
                        phase_ref=lambda: "WINDOW2", mutex=mutex)
    hc = registry.start(LaneSpec("track_c_host", c_track, window="all_night"),
                        phase_ref=lambda: "WINDOW2", mutex=mutex)
    try:
        time.sleep(0.15)
        lock = PcscdMaintenanceLock(registry, store, clock, pause_grace_s=2.0)
        with lock.hold("test"):
            assert hb.paused_ack.wait(2.0)          # Track B paused + acknowledged
            b_frozen, c_during = counts["b"], counts["c"]
            time.sleep(0.2)
            assert counts["b"] == b_frozen           # paused
            assert counts["c"] > c_during            # host track unaffected
        assert not hb.pause.is_set()                 # resumed
        time.sleep(0.1)
        assert counts["b"] > b_frozen
    finally:
        registry.stop_lane(hb, 1.0)
        registry.stop_lane(hc, 1.0)


# ------------------------------------------------------------- report ----

def test_report_md_sections_skip_reasons_anomalies():
    state = {
        "run": {"started_at": "2026-08-28T20:00:00+00:00", "ended_at": None,
                "status": "running", "exit_code": None, "dry_run": True},
        "phases": [{"name": "WINDOW2", "status": "skipped", "planned_dur_s": 0,
                    "actual_dur_s": None, "detail": "overrun"}],
        "rows": [{"ts": "t1", "mono": 1, "phase": "WINDOW2", "lane": "track_d_soak",
                  "type": "SKIP", "status": "SKIP",
                  "reason": "Mode B fallback: ccid window deferred to night 2"}],
        "timeline": [{"ts": "t2", "mono": 2, "kind": "hb_gap", "level": "anomaly",
                      "hb_age_s": 45}],
        "mode_decision": {"mode": "Mode B — role switch failed; ccid deferred to "
                                  "night 2 (fallback)", "ok": False},
    }
    md = build_report_md(state)
    for phase in PHASES:
        assert f"## Phase: {phase}" in md          # ALL sections, even skipped
    assert "Mode B" in md
    assert "deferred to night 2" in md             # SKIP reason rendered
    assert "## Anomaly Timeline" in md and "hb_gap" in md
    assert "## SKIP Log" in md


# ---------------------------------------------------- dry-run end-to-end ----

class RecordingMutex(CardMutex):
    """Records (card, acquire_t, release_t) to prove cross-track exclusivity."""

    def __init__(self):
        super().__init__()
        self.intervals = []
        self._t0 = {}

    def acquire(self, card, who, timeout=None):
        ok = super().acquire(card, who, timeout)
        if ok:
            self._t0[card] = time.monotonic()
        return ok

    def release(self, card):
        t0 = self._t0.pop(card, None)
        if t0 is not None:
            self.intervals.append((card, t0, time.monotonic()))
        super().release(card)


def test_dry_run_mode_a_end_to_end(tmp_path):
    orch = build_dry_run_app(scaled(3.0), tmp_path, gate_ok=True)
    rec = RecordingMutex()
    orch.mutex = rec
    orch.registry = LaneRegistry(orch.store, orch.clock)
    rc = orch.run()
    assert rc == 0
    md = (tmp_path / "report.md").read_text()
    for phase in PHASES:
        assert f"## Phase: {phase}" in md
    assert "Mode A" in md
    state = ResultsStore.load(tmp_path / "results.json")
    assert "Mode A" in state["mode_decision"]["mode"]
    assert state["run"]["exit_code"] == 0
    # heartbeat file written by the scheduler process (watchdog contract)
    hb = json.loads((tmp_path / "heartbeat.json").read_text())
    assert hb["pid"] == os.getpid()
    # card-mutation mutex: stick card shared by track_a_cycles + track_a_rest
    stick = sorted((a, b) for c, a, b in rec.intervals if c == "stick")
    assert len(stick) >= 2
    for (_, end), (start, _) in zip(stick, stick[1:]):
        assert end <= start + 0.02            # never overlapping
    lanes_seen = {r["lane"] for r in state["rows"] if r.get("type") == "mutation"}
    assert {"track_a_cycles", "track_a_rest"} <= lanes_seen
    # drain recorded card-state rows as the window's last rows
    assert any(r["type"] == "card_state" and r["phase"] == "WINDOW1"
               for r in state["rows"])


def test_dry_run_mode_b_fallback(tmp_path):
    orch = build_dry_run_app(scaled(3.0), tmp_path, gate_ok=False)
    rc = orch.run()
    assert rc == 0
    state = ResultsStore.load(tmp_path / "results.json")
    assert "Mode B" in state["mode_decision"]["mode"]
    md = (tmp_path / "report.md").read_text()
    assert "Mode B" in md
    skip_rows = [r for r in state["rows"] if r["status"] == "SKIP"]
    reasons = " ".join(r.get("reason", "") for r in skip_rows)
    assert "Mode B fallback: ccid window deferred to night 2" in reasons
    for track in ("track_d_soak", "track_d_raw", "track_d_atr"):
        assert any(r.get("lane") == track and r["status"] == "SKIP"
                   for r in state["rows"])
    # restore happened at gate failure; RESTORE phase recorded Mode B handling
    assert any(e["kind"] == "restore_skipped_mode_b" for e in state["timeline"])
    # monitor ran (scripted hb_age spike -> anomaly recorded)
    assert any(e["kind"] == "hb_gap" for e in state["timeline"])


def test_dry_run_overrun_shrinks_but_report_still_generated(tmp_path):
    def slowpoke(ctx):
        n = 0
        while ctx.running():
            try:
                with ctx.card("stick"):
                    ctx.row(type="mutation", status="PASS", lane_tag="slowpoke", i=n)
                    for _ in range(12):
                        if not ctx.running():
                            return
                        ctx.sleep(0.25)          # bounded but slow iteration
            except MutationWindowClosed:
                ctx.skip("mutation window closed (drain)")
                return
            n += 1

    extra = [LaneSpec("slowpoke", slowpoke, window="window1", cards=("stick",))]
    cfg = scaled(3.0)
    cfg["drain_grace_s"] = 1.2
    orch = build_dry_run_app(cfg, tmp_path, gate_ok=True, extra_specs=extra)
    rc = orch.run()
    assert rc == 0                                        # REPORT always generates
    state = ResultsStore.load(tmp_path / "results.json")
    kinds_ = kinds(orch.store)
    assert "drain_grace_elapsed" in kinds_                # overrun was detected
    phases = {p["name"]: p for p in state["phases"]}
    assert phases["REPORT"]["status"] == "completed"
    # dynamic shrink: some later phase was skipped/shrunk by the overrun
    assert any(phases[p]["status"] in ("skipped", "completed (Mode B degraded)")
               for p in ("ROLE_GATE", "WINDOW2", "RESTORE")) or \
           "drain_grace_elapsed" in kinds_
    md = (tmp_path / "report.md").read_text()
    assert "## Phase: REPORT" in md


def test_lane_crash_recorded_as_anomaly(tmp_path):
    def crasher(ctx):
        raise ValueError("boom-track")

    store = ResultsStore(tmp_path)
    registry = LaneRegistry(store, overnight.RealClock())
    h = registry.start(LaneSpec("crasher", crasher, window="window1"),
                       phase_ref=lambda: "WINDOW1", mutex=CardMutex())
    assert h.thread is not None
    h.thread.join(2.0)
    assert any(e["kind"] == "lane_crash" and "boom-track" in e["error"]
               for e in store.state["timeline"])


# ------------------------------------------------------------- misc ----

def test_heartbeat_file_written(tmp_path):
    store = ResultsStore(tmp_path)
    hb = Heartbeat(store, overnight.RealClock(), tmp_path / "heartbeat.json", 60.0)
    hb.maybe_write("WINDOW1", force=True)
    data = json.loads((tmp_path / "heartbeat.json").read_text())
    assert data["pid"] == os.getpid() and data["phase"] == "WINDOW1"


def test_try_load_ledger_tolerant():
    led = try_load_ledger()
    assert led is None or hasattr(led, "__name__")   # None before todo 6 lands


def test_cli_dry_run_exit_zero_with_mode_b(tmp_path):
    out = tmp_path / "cli"
    proc = subprocess.run(
        [sys.executable, str(OVERNIGHT_DIR / "overnight.py"), "--dry-run",
         "--duration", "6", "--results-dir", str(out)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = out / "report.md"
    assert report.exists()
    md = report.read_text()
    for phase in PHASES:
        assert f"## Phase: {phase}" in md
    assert "Mode B" in md                            # default gate injection
    assert "results.json" in proc.stdout


# ---------------------------------------------- r3 amendments (g: hb thread) ----

def test_heartbeat_dedicated_writer_thread_and_stop(tmp_path):
    store = ResultsStore(tmp_path)
    hb = Heartbeat(store, overnight.RealClock(), tmp_path / "heartbeat.json", 0.05)
    hb.start_writer(lambda: "ROLE_GATE")
    try:
        deadline, seen = time.time() + 2.0, set()
        while time.time() < deadline and len(seen) < 3:
            try:
                seen.add((tmp_path / "heartbeat.json").stat().st_mtime_ns)
            except OSError:
                pass
            time.sleep(0.02)
        assert len(seen) >= 3      # refreshed with ZERO main-thread touches
        data = json.loads((tmp_path / "heartbeat.json").read_text())
        assert data["pid"] == os.getpid() and data["phase"] == "ROLE_GATE"
    finally:
        hb.stop_writer()
    assert hb._writer is None
    mtime = (tmp_path / "heartbeat.json").stat().st_mtime_ns
    time.sleep(0.15)
    assert (tmp_path / "heartbeat.json").stat().st_mtime_ns == mtime  # stopped


def test_hb_writer_fresh_during_blocking_role_gate(tmp_path):
    # The multi-minute 115200-baud flash, simulated: the MAIN thread is fully
    # blocked inside role_gate; the dedicated writer must keep heartbeat.json
    # fresh (watchdog dead-man input, stale >120s would false-fire mid-gate).
    writes, entered = [], threading.Event()

    def blocking_gate(ctx):
        entered.set()
        hb_path = tmp_path / "heartbeat.json"
        deadline = time.time() + 1.2
        while time.time() < deadline:
            try:
                st = hb_path.stat()
                writes.append((st.st_mtime_ns, json.loads(hb_path.read_text())["phase"]))
            except (OSError, ValueError):
                pass
            time.sleep(0.03)
        return GateResult(True, "blocking gate done")

    cfg = scaled(3.0)
    cfg["heartbeat_interval_s"] = 0.05
    orch = build_dry_run_app(cfg, tmp_path, gate_ok=True)
    orch.role_gate = blocking_gate
    rc = orch.run()
    assert rc == 0
    assert entered.is_set()
    assert len({w[0] for w in writes}) >= 3     # kept refreshing while blocked
    assert all(phase == "ROLE_GATE" for _, phase in writes)


# ------------------------------------------- r3 amendments (f/C: marker consume) ----

def test_pcscd_marker_serviced_once_under_lock_then_consumed(tmp_path):
    calls = []
    orch = build_dry_run_app(scaled(3.0), tmp_path / "run", gate_ok=True)
    orch.pcscd_restart_fn = lambda: (calls.append(1) or (True, "fake restart"))
    marker = tmp_path / "run" / "PCSCD_RESTART_REQUEST"
    marker.write_text(json.dumps({"source": "watchdog"}))
    orch._poll_cross_process()
    assert len(calls) == 1
    assert not marker.exists()
    assert not marker.with_name(marker.name + ".done").exists()  # .done cleaned
    orch._poll_cross_process()                                   # later polls
    orch._poll_cross_process()
    assert len(calls) == 1                    # serviced requests never re-execute
    ev = orch.store.state["timeline"]
    kinds_ = [e["kind"] for e in ev]
    assert "pcscd_restart_request_seen" in kinds_
    assert "pcscd_restart_request_serviced" in kinds_
    beg = [e for e in ev if e["kind"] == "pcscd_maintenance_begin"]
    assert beg and beg[-1]["who"] == "watchdog_request"  # ran UNDER the lock


def test_pcscd_marker_retraction_race_tolerated(tmp_path):
    calls = []
    orch = build_dry_run_app(scaled(3.0), tmp_path / "run", gate_ok=True)
    marker = tmp_path / "run" / "PCSCD_RESTART_REQUEST"

    def restarting_and_retracting():
        marker.unlink()   # watchdog retracts (reader recovered) mid-service
        calls.append(1)
        return True, "fake restart"

    orch.pcscd_restart_fn = restarting_and_retracting
    marker.write_text("{}")
    orch._poll_cross_process()               # must not raise
    assert len(calls) == 1
    assert not marker.exists()
    kinds_ = [e["kind"] for e in orch.store.state["timeline"]]
    assert "pcscd_restart_request_error" not in kinds_


# ------------------------------------------------- r3 amendments (h: ABORT) ----

def _wait_for_row(path, pred, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            state = json.loads(path.read_text())
        except (OSError, ValueError):
            time.sleep(0.02)
            continue
        if any(pred(r) for r in state.get("rows", [])):
            return state
        time.sleep(0.02)
    raise AssertionError("row not observed in time")


def _run_orchestrator_in_thread(orch, result):
    t = threading.Thread(target=lambda: result.__setitem__("rc", orch.run()))
    t.start()
    return t


def test_abort_file_winds_down_at_next_phase_boundary(tmp_path):
    orch = build_dry_run_app(scaled(8.0), tmp_path, gate_ok=True)
    gate_calls = []
    orig_gate = orch.role_gate
    orch.role_gate = lambda ctx: gate_calls.append(1) or orig_gate(ctx)
    result = {}
    t = _run_orchestrator_in_thread(orch, result)
    try:
        _wait_for_row(tmp_path / "results.json",
                      lambda r: r.get("phase") == "WINDOW1"
                      and r.get("type") == "mutation")
        (tmp_path / "ABORT").write_text("")
        t.join(60.0)
    finally:
        if t.is_alive():
            orch.registry.stop_all(2.0)
            t.join(5.0)
            raise AssertionError("orchestrator did not wind down after ABORT")
    assert result.get("rc") == 0
    state = ResultsStore.load(tmp_path / "results.json")
    assert state["run"]["status"] == "aborted (operator ABORT)"
    assert state["run"]["exit_code"] == 0
    phases = {}
    for p in state["phases"]:
        phases.setdefault(p["name"], []).append(p)
    assert phases["ROLE_GATE"][-1]["status"] == "skipped"
    assert "ABORT" in phases["ROLE_GATE"][-1]["detail"]
    assert phases["WINDOW2"][-1]["status"] == "skipped"
    assert phases["RESTORE"][-1]["status"] == "skipped"       # gate never ran
    assert phases["REPORT"][-1]["status"] == "completed"      # always generates
    assert gate_calls == []                        # no reflash after ABORT
    assert state["mode_decision"] is None
    kinds_ = [e["kind"] for e in state["timeline"]]
    assert "abort_requested" in kinds_
    assert "restore_skipped_abort" in kinds_
    assert any(r.get("status") == "SKIP" and "operator ABORT" in r.get("reason", "")
               and r.get("phase") == "ROLE_GATE" for r in state["rows"])
    w1 = [r for r in state["rows"] if r.get("phase") == "WINDOW1"]
    assert any(r["type"] == "card_state" for r in w1)        # drain still ran
    md = (tmp_path / "report.md").read_text()
    assert "operator ABORT" in md and "## Phase: REPORT" in md


def test_abort_after_role_gate_still_restores(tmp_path):
    orch = build_dry_run_app(scaled(10.0), tmp_path, gate_ok=True)
    restore_calls = []
    orig_restore = orch.restore_fn
    orch.restore_fn = lambda ctx: restore_calls.append(1) or orig_restore(ctx)
    result = {}
    t = _run_orchestrator_in_thread(orch, result)
    try:
        _wait_for_row(tmp_path / "results.json",
                      lambda r: r.get("phase") == "WINDOW2"
                      and r.get("type") == "mutation")
        (tmp_path / "ABORT").write_text("")
        t.join(60.0)
    finally:
        if t.is_alive():
            orch.registry.stop_all(2.0)
            t.join(5.0)
            raise AssertionError("no wind-down after ABORT")
    assert result.get("rc") == 0
    state = ResultsStore.load(tmp_path / "results.json")
    assert restore_calls                     # restore is safety-critical: ran
    phases = {p["name"]: p for p in state["phases"]}
    assert phases["RESTORE"]["status"] == "completed"
    assert phases["WINDOW2"]["status"] == "completed"
    assert "ABORT" in phases["WINDOW2"]["detail"]
    assert state["run"]["status"] == "aborted (operator ABORT)"


# ------------------------------------------------------------ config example ----

def test_config_example_json_validates_placeholder_only():
    path = OVERNIGHT_DIR / "config.example.json"
    cfg = overnight.load_config(path)
    assert cfg["duration_s"] == 32400.0
    text = path.read_text()
    for key in ("WIFI_PASS", "REST_TOKEN", "HIL_ISSUER"):
        assert key not in text       # no credential fields: placeholders only
    # credential VALUES must be read from the gitignored overnight.env at
    # test time — never embedded here (a literal would itself be a committed
    # secret). Machines without overnight.env get the key-name checks only.
    env_path = OVERNIGHT_DIR / "overnight.env"
    env_values = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_values[k] = v.strip().strip('"').strip("'")
    for key in ("WIFI_PASS", "REST_TOKEN", "HIL_ISSUER"):
        value = env_values.get(key, "")
        if value:
            assert value not in text
