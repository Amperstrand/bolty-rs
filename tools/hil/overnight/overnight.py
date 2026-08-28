#!/usr/bin/env python3
"""Overnight HIL orchestrator core (plan todo 5).

Phase-gated scheduler for the unattended dual-role audit night:

    PREFLIGHT -> WINDOW1 (bolty) -> ROLE_GATE -> WINDOW2 (ccid) -> RESTORE -> REPORT

Hard invariants (Metis amendments a-f):
  a. CROSS-TRACK CARD-MUTATION MUTEX — exactly one track may issue card-mutating
     commands to a given card at a time. REST jobs and console burn cycles share
     the ``stick`` card; Track B owns ``acr`` (Track D soak shares it in window 2).
  b. WINDOW DRAIN — at each window's T-5min mark the mutation window CLOSES (no
     new mutations), in-flight card locks get <=70s grace to clear, a card-state
     row (inspect) is recorded as the window's last row, then the handoff runs.
  c. HARD WALL-CLOCK END — every phase has a FIXED end anchor computed from the
     configured start+duration; a late phase SHRINKS (never extends into the next
     phase) so REPORT always generates at the configured end time.
  d. INCREMENTAL STATE — every row/event is persisted immediately via
     write-temp+os.replace, so a dead scheduler still leaves a complete partial
     results.json; report.md is regenerated at every phase boundary and is
     rebuildable from results.json alone (see ``ResultsStore.load`` +
     ``build_report_md`` — used by the watchdog, todo 16).
  e. console.log timestamps are ``%H:%M:%S`` without a date — HB-gap detection
     NEVER uses them. Gaps come from the daemon PING ``hb_age`` (receive time);
     the file tail only feeds nfc=DOWN and t= (uptime ms) regression detection.
  f. GLOBAL PCSCD-MAINTENANCE LOCK — every lane that consumes pcscd (Track B AND
     Track D soak) is paused while pcscd is stopped/restarted (role switch,
     raw framing abuse). Pause is acknowledged; a stuck lane never blocks the
     restart beyond the pause grace (it gets an anomaly row instead).
     Cross-process requests (todo-16 watchdog) use a
     ``results/<date>/PCSCD_RESTART_REQUEST`` marker: the scheduler's monitor
     executes the restart UNDER this lock, then atomically CONSUMES the marker
     (rename to ``.done`` then delete) so a serviced request never re-executes
     (oracle r3: a never-cleared marker would restart pcscd every cycle).
  g. HEARTBEAT FRESHNESS IS THREAD-INDEPENDENT — ``heartbeat.json`` (the
     todo-16 watchdog dead-man input: ``{"pid","ts","phase"}``, stale >120s)
     is maintained by a DEDICATED hb-writer thread, so freshness (<=60s) is
     independent of long-blocking scheduler phases: the multi-minute
     115200-baud role-gate flash, preflight checks, drain grace waits
     (oracle r3: a synchronous flash would otherwise stale hb >120s and
     false-fire the one-shot dead-man mid-gate).
  h. ABORT POLL — the scheduler main loop polls ``results/<date>/ABORT``
     alongside heartbeat maintenance (every wait tick + each phase boundary)
     and winds all lanes down at the next phase boundary: the current window
     still drains (in-flight ops <=70s, card-state rows), ROLE_GATE/WINDOW2
     are skipped, RESTORE runs only if the role gate already executed, and
     REPORT always generates (oracle r3: an independent watchdog cannot
     gracefully stop scheduler lanes — ABORT is cooperative).

=============================================================================
 LANE API — contract for track implementers (todos 7-16). Code against this
 docstring; you should never need to read the internals below.
=============================================================================

Import styles (pick ONE per process; do not mix):
  A. ``sys.path.insert(0, "<repo>/tools/hil/overnight"); import overnight``
     (binds this file as module ``overnight`` — what tests do).
  B. from repo root: ``from tools.hil.overnight import overnight`` (namespace
     packages make this work; same file, different module object).

A *track* is a plain callable ``target(ctx: PhaseContext) -> None`` wrapped in a
``LaneSpec(name, target, window=..., cards=..., needs_pcscd=...)``:

    def my_track(ctx):
        n = 0
        while ctx.running():
            try:
                with ctx.card("stick"):          # card-mutation mutex; also
                    do_one_bounded_mutation()    # enforces the drain window.
            except overnight.MutationWindowClosed:
                ctx.skip("mutation window closed (drain)")   # honest SKIP row
                break
            ctx.row(type="cycle", status="PASS", i=n)
            n += 1
            ctx.sleep(ctx.pace_s)   # pause-aware (pcscd maintenance) sleeping

Rules:
  * Every iteration MUST be bounded (finish well under drain_grace_s, 70s) —
    overrun policy is "finish current bounded iteration, SKIP the remainder".
  * NEVER hold ``ctx.card()`` across ``ctx.sleep()``.
  * Never call mutating hardware outside ``with ctx.card(...)``. Read-only ops
    (status, uid, poll) do not need the lock.
  * All-night tracks (Track B/C: ``window="all_night"``) have no drain window;
    they are paused automatically around pcscd maintenance (needs_pcscd=True)
    and must tolerate transport errors during that pause WITHOUT counting them
    as card-auth failures (ledger classification, todo 6).
  * A crashing track is recorded as an anomaly row and never kills the run.

``PhaseContext`` members: ``name``, ``cards``, ``pace_s``, ``dry_run``,
``ledger`` (todo-6 module or None), ``running()``, ``paused()``, ``sleep(s)``,
``card(card_id)`` (context manager raising ``MutationWindowClosed``),
``row(**fields)``, ``skip(reason, **fields)``, ``anomaly(kind, **fields)``,
``event(kind, **fields)``.

Other extension points (all injectable, all hardware-free by default):
  * ``role_gate(ctx) -> GateResult(ok, detail)`` — todo 15 (switch_role mirror).
  * ``restore_fn(ctx) -> GateResult`` — switch back to bolty.
  * ``preflight_fn(ctx) -> bool`` — todo 18 checks.
  * ``probes: {card_id: callable() -> dict}`` — drain card-state rows
    (todo 7/10 register inspect probes; builtin ``console_inspect_probe``).
  * Track modules are imported tolerantly by name (``track_a`` etc.); missing
    modules become honest SKIP rows, never crashes.

Results layout (per run dir): ``results.json`` (incremental, atomic),
``report.md`` (regenerated at each phase boundary + end), ``heartbeat.json``
(pid + freshness <=60s while the scheduler lives, kept fresh by the dedicated
hb-writer thread — the todo-16 watchdog monitors this file and rebuilds the
morning report if we die).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

PHASES = ("PREFLIGHT", "WINDOW1", "ROLE_GATE", "WINDOW2", "RESTORE", "REPORT")

HB_MAX_AGE_S = 30.0  # spec: HB gap > 30s is an anomaly
DRAIN_LEAD_S = 300.0  # T-5min mutation stop
DRAIN_GRACE_S = 70.0  # <=70s wait for in-flight card ops
PCSCD_PAUSE_GRACE_S = 90.0
HEARTBEAT_INTERVAL_S = 60.0
ABORT_FILENAME = "ABORT"  # operator touch -> cooperative wind-down (req. h)
PCSCD_RESTART_MARKER = "PCSCD_RESTART_REQUEST"  # watchdog -> scheduler (req. f)

# Dry-run floors (seconds) so a compressed timeline still exercises real
# thread scheduling margins rather than degenerate zero-second waits.
DRY_FLOORS = {
    "drain_lead_s": 0.20,
    "drain_grace_s": 1.20,
    "hb_poll_s": 0.05,
    "heartbeat_interval_s": 0.20,
    "pcscd_pause_grace_s": 1.00,
    "pace_s": 0.02,
    "lane_join_s": 1.00,
}
DRY_TOTAL_S = 24.0  # default compressed timeline for `--dry-run`

DEFAULT_CONFIG = {
    "duration_s": 32400.0,  # 22:00 -> 07:00
    "phases": {
        "preflight_s": 1800.0,
        "window1_s": 12600.0,
        "role_gate_s": 1800.0,
        "window2_s": 12600.0,
        "restore_s": 2700.0,
        "report_s": 900.0,
    },
    "drain_lead_s": DRAIN_LEAD_S,
    "drain_grace_s": DRAIN_GRACE_S,
    "pcscd_pause_grace_s": PCSCD_PAUSE_GRACE_S,
    "heartbeat_interval_s": HEARTBEAT_INTERVAL_S,
    "lane_join_s": 5.0,
    "cards": {"stick": {"probe": "console_inspect"}, "acr": {"probe": "bolty_cli_inspect"}},
    "hb": {"enabled": True, "max_age_s": HB_MAX_AGE_S, "poll_s": 10.0,
           "console_log": "~/.bolty/console.log", "console_socket": "/run/bolty/console.sock"},
    "monitor_phases": ["WINDOW1", "RESTORE"],
    "window1_tracks": ["track_a_cycles"],
    "window2_ccid_tracks": ["track_d_soak", "track_d_raw", "track_d_atr"],
    "all_night_tracks": ["track_b_acr", "track_c_host"],
}


class ConfigError(Exception):
    pass


class MutationWindowClosed(Exception):
    """Raised by ctx.card(): drain closed the mutation window, or lock timeout."""

    def __init__(self, card: str, reason: str = ""):
        super().__init__(f"mutation window closed for card {card!r}: {reason}")
        self.card, self.reason = card, reason or "closed"


@dataclass
class GateResult:
    ok: bool
    detail: str = ""


# ---------------------------------------------------------------- clocks ----

class RealClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def time(self) -> float:
        return time.time()

    def sleep(self, s: float) -> None:
        if s > 0:
            time.sleep(s)

    def wait(self, ev: threading.Event, timeout: Optional[float]) -> bool:
        return ev.wait(timeout)


class FakeClock:
    """Deterministic single-threaded clock (never use with real threads)."""

    def __init__(self, t0: float = 0.0, wall: float = 1_800_000_000.0):
        self._mono, self._wall = t0, wall

    def monotonic(self) -> float:
        return self._mono

    def time(self) -> float:
        return self._wall

    def sleep(self, s: float) -> None:
        self._mono += max(0.0, s)

    def wait(self, ev: threading.Event, timeout: Optional[float]) -> bool:
        deadline = self._mono + (1e18 if timeout is None else max(0.0, timeout))
        while not ev.is_set():
            if self._mono >= deadline:
                return False
            self._mono += 0.01
        return True


# ---------------------------------------------------------------- config ----

def merge_defaults(cfg: dict) -> dict:
    out = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    for k, v in cfg.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def validate_config(cfg: dict) -> dict:
    cfg = merge_defaults(cfg)
    try:
        total = float(cfg["duration_s"])
        ph = {k: float(v) for k, v in cfg["phases"].items()}
    except (KeyError, TypeError, ValueError) as e:
        raise ConfigError(f"bad numeric config: {e}") from e
    missing = [p for p in ("preflight_s", "window1_s", "role_gate_s",
                           "window2_s", "restore_s", "report_s") if p not in ph]
    if missing:
        raise ConfigError(f"phases missing budgets: {missing}")
    if total <= 0 or any(v <= 0 for v in ph.values()):
        raise ConfigError("durations must be positive")
    if abs(sum(ph.values()) - total) > 1.0:
        raise ConfigError(f"phase budgets sum to {sum(ph.values())}s != duration_s {total}s")
    lead = float(cfg["drain_lead_s"])
    if lead >= min(ph["window1_s"], ph["window2_s"]):
        raise ConfigError("drain_lead_s must be smaller than the windows")
    if not cfg["cards"]:
        raise ConfigError("config must define at least one card")
    return cfg


def load_config(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return validate_config(json.load(f))


def scale_config(cfg: dict, total_s: float, dry: bool = False) -> dict:
    """Compress the timeline to total_s (dry-run); apply dry floors."""
    cfg = json.loads(json.dumps(cfg))
    factor = total_s / float(cfg["duration_s"])
    cfg["duration_s"] = total_s
    cfg["phases"] = {k: v * factor for k, v in cfg["phases"].items()}
    for k in ("drain_lead_s", "drain_grace_s", "pcscd_pause_grace_s",
              "heartbeat_interval_s", "lane_join_s"):
        cfg[k] = float(cfg[k]) * factor
    cfg["hb"]["poll_s"] = float(cfg["hb"]["poll_s"]) * factor
    if dry:
        for k, floor in DRY_FLOORS.items():
            if k in cfg:
                cfg[k] = max(float(cfg[k]), floor)
        cfg["hb"]["poll_s"] = max(float(cfg["hb"]["poll_s"]), DRY_FLOORS["hb_poll_s"])
        lead = min(cfg["drain_lead_s"], 0.25 * min(cfg["phases"]["window1_s"],
                                                    cfg["phases"]["window2_s"]))
        cfg["drain_lead_s"] = max(lead, DRY_FLOORS["drain_lead_s"] * 0.5)
    return cfg


# ------------------------------------------------------------ result store ----

def _atomic_write_json(path: Path, obj: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class ResultsStore:
    """Incremental atomic persistence: every row/event rewrites results.json
    via write-temp+rename, so a dead scheduler leaves a complete partial state."""

    def __init__(self, directory: str | Path, clock=None):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.clock = clock or RealClock()
        self.path = self.dir / "results.json"
        self.report_path = self.dir / "report.md"
        self._lock = threading.Lock()
        self.state = {
            "run": {"started_at": None, "ended_at": None, "dry_run": False,
                    "exit_code": None, "status": "starting"},
            "phases": [],
            "rows": [],
            "timeline": [],
            "mode_decision": None,
        }

    def _persist(self) -> None:
        with self._lock:
            _atomic_write_json(self.path, self.state)

    def mark_started(self, dry_run: bool) -> None:
        self.state["run"].update(started_at=_iso(self.clock.time()), dry_run=dry_run,
                                 status="running")
        self._persist()

    def row(self, **fields) -> dict:
        r = {"ts": _iso(self.clock.time()), "mono": round(self.clock.monotonic(), 4),
             "phase": fields.pop("phase", None), "lane": fields.pop("lane", None),
             "type": fields.get("type", "info"), "status": fields.get("status", "INFO")}
        r.update(fields)
        with self._lock:
            self.state["rows"].append(r)
        self._persist()
        return r

    def event(self, kind: str, level: str = "info", **fields) -> dict:
        e = {"ts": _iso(self.clock.time()), "mono": round(self.clock.monotonic(), 4),
             "kind": kind, "level": level}
        e.update(fields)
        with self._lock:
            self.state["timeline"].append(e)
        self._persist()
        return e

    def anomaly(self, kind: str, **fields) -> dict:
        return self.event(kind, level="anomaly", **fields)

    def begin_phase(self, name: str, planned_dur_s: float, planned_start: float = None) -> None:
        with self._lock:
            self.state["phases"].append({"name": name, "status": "running",
                                         "started_at": _iso(self.clock.time()),
                                         "planned_dur_s": round(planned_dur_s, 3),
                                         "actual_dur_s": None, "detail": ""})
        self._persist()

    def end_phase(self, name: str, status: str, detail: str = "") -> None:
        with self._lock:
            for p in reversed(self.state["phases"]):
                if p["name"] == name and p["status"] == "running":
                    p.update(status=status, detail=detail,
                             ended_at=_iso(self.clock.time()),
                             actual_dur_s=None)
                    break
        self._persist()

    def set_mode(self, decision: dict) -> None:
        with self._lock:
            self.state["mode_decision"] = decision
            self.state["run"]["mode"] = decision.get("mode")
        self.row(type="mode_decision", status="PASS" if decision.get("ok") else "FALLBACK",
                 **{k: v for k, v in decision.items() if k != "ok"})
        self._persist()

    def finish(self, exit_code: int, status: str = "completed") -> None:
        self.state["run"].update(ended_at=_iso(self.clock.time()),
                                 exit_code=exit_code, status=status)
        self._persist()

    @classmethod
    def load(cls, path: str | Path) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------ heartbeat writer ----

class Heartbeat:
    def __init__(self, store: ResultsStore, clock, path: str | Path, interval_s: float):
        self.store, self.clock = store, clock
        self.path = Path(path)
        self.interval = max(0.05, float(interval_s))
        self._next_at = 0.0
        self._wlock = threading.Lock()  # main-thread touches vs writer thread
        self._writer_stop = threading.Event()
        self._writer: Optional[threading.Thread] = None

    def maybe_write(self, phase: str, force: bool = False) -> None:
        with self._wlock:
            now = self.clock.monotonic()
            if not force and now < self._next_at:
                return
            self._next_at = now + self.interval
            _atomic_write_json(self.path, {"pid": os.getpid(), "ts": _iso(self.clock.time()),
                                           "phase": phase})

    def start_writer(self, phase_ref: Callable[[], str]) -> None:
        """Dedicated hb-writer thread (requirement g, oracle r3): heartbeat
        freshness is INDEPENDENT of long-blocking scheduler phases (the
        multi-minute 115200-baud role-gate flash, preflight, drain grace),
        so the todo-16 dead-man (hb stale >120s) never false-fires mid-gate
        while the scheduler lives."""
        if self._writer is not None:
            return
        self._writer_stop.clear()

        def loop():
            while not self._writer_stop.is_set():
                try:
                    self.maybe_write(phase_ref())
                except Exception as e:  # noqa: BLE001 — the writer must survive
                    print(f"[overnight] heartbeat write failed: {e!r}", file=sys.stderr)
                self.clock.wait(self._writer_stop, self.interval)

        self._writer = threading.Thread(target=loop, name="scheduler-hb", daemon=True)
        self._writer.start()

    def stop_writer(self) -> None:
        """A dead/fatal scheduler must STOP heartbeating so the dead-man can
        fire (a lingering fresh hb would mask a dead scheduler)."""
        self._writer_stop.set()
        if self._writer is not None:
            self._writer.join(timeout=2.0)
            self._writer = None


# ---------------------------------------------------------- console HB ----

HB_RE = re.compile(r"\[HB\]\s+alive\s+t=(\d+)ms\s+nfc=(ok|DOWN)")


@dataclass
class HB:
    t_ms: int
    nfc_ok: bool


def parse_hb_line(line: str) -> Optional[HB]:
    m = HB_RE.search(line)
    if not m:
        return None
    return HB(t_ms=int(m.group(1)), nfc_ok=m.group(2) == "ok")


def ping_daemon(socket_path: str, timeout: float = 5.0) -> dict:
    """One PING to bolty-console (daemon health; never touches the tty)."""
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
        m = re.search(r"hb_age=(-?\d+)s", text)
        return {"hb_age": int(m.group(1)) if m else None, "lines": text.splitlines(),
                "error": None}
    except OSError as e:
        return {"hb_age": None, "lines": [], "error": repr(e)}


class ConsoleMonitor:
    """HB anomaly monitor.

    Gap detection uses ONLY receive-time sources: the daemon PING hb_age (primary)
    and the wall time at which we receive each tailed line — NEVER the %H:%M:%S
    console.log timestamps (no date; they wrap at midnight, Metis e).
    The file tail feeds nfc=DOWN and t= (uptime ms) regression detection.
    """

    def __init__(self, sink: Callable[[dict], None], clock, *, max_age_s: float = HB_MAX_AGE_S,
                 poll_s: float = 10.0, ping: Optional[Callable[[], dict]] = None,
                 log_path: Optional[str] = None):
        self.sink, self.clock = sink, clock
        self.max_age_s, self.poll_s = float(max_age_s), float(poll_s)
        self.ping = ping
        self.log_path = os.path.expanduser(log_path) if log_path else None
        self._tail_off = 0
        self._tail_missing_note = False
        self._last_hb_mono = None
        self._last_t_ms = None
        self._nfc_down = False
        self._ping_alert = False
        self._stop = threading.Event()
        self._thread = None

    # -- parsing/anomaly core (unit-testable, must never raise) -------------
    def feed_line(self, line: str, recv_mono: Optional[float] = None) -> None:
        try:
            hb = parse_hb_line(line)
            if hb is None:
                return
            now = self.clock.monotonic() if recv_mono is None else recv_mono
            if self._last_hb_mono is not None and (now - self._last_hb_mono) > self.max_age_s:
                self.sink({"kind": "hb_gap", "source": "console_tail",
                           "gap_s": round(now - self._last_hb_mono, 1)})
            if not hb.nfc_ok and not self._nfc_down:
                self.sink({"kind": "nfc_down", "source": "console_tail", "line": line.strip()})
            self._nfc_down = not hb.nfc_ok
            if self._last_t_ms is not None and hb.t_ms < self._last_t_ms:
                self.sink({"kind": "t_regression", "source": "console_tail",
                           "t_ms": hb.t_ms, "prev_t_ms": self._last_t_ms})
            self._last_hb_mono, self._last_t_ms = now, hb.t_ms
        except Exception as e:  # corrupted/garbage input must never kill the monitor
            self.sink({"kind": "monitor_error", "source": "feed_line", "error": repr(e)})

    def check_ping(self, ping: dict) -> None:
        if ping.get("error"):
            self.sink({"kind": "console_ping_error", "error": ping["error"]})
            self._ping_alert = False
            return
        age = ping.get("hb_age")
        if age is None:
            return
        if age > self.max_age_s and not self._ping_alert:
            self.sink({"kind": "hb_gap", "source": "daemon_ping", "hb_age_s": age})
            self._ping_alert = True
        elif age <= self.max_age_s:
            self._ping_alert = False

    def tail_lines(self) -> None:
        if not self.log_path:
            return
        try:
            size = os.path.getsize(self.log_path)
        except OSError:
            if not self._tail_missing_note:
                self.sink({"kind": "console_log_missing", "path": self.log_path})
                self._tail_missing_note = True
            return
        self._tail_missing_note = False
        if size < self._tail_off:  # truncated/rotated — restart from 0, no panic
            self._tail_off = 0
        try:
            with open(self.log_path, "r", encoding="latin1", errors="replace") as f:
                f.seek(self._tail_off)
                data = f.read()
                self._tail_off = f.tell()
        except OSError as e:
            self.sink({"kind": "console_log_error", "error": repr(e)})
            return
        for line in data.splitlines():
            self.feed_line(line)

    def poll_once(self) -> None:
        if self.ping is not None:
            self.check_ping(self.ping())
        self.tail_lines()

    # -- threaded lifecycle --------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()

        def loop():
            while not self._stop.is_set():
                try:
                    self.poll_once()
                except Exception as e:  # noqa: BLE001 — monitor must never die silently
                    self.sink({"kind": "monitor_error", "error": repr(e)})
                self.clock.wait(self._stop, self.poll_s)

        self._thread = threading.Thread(target=loop, name="hb-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


# ------------------------------------------------- card mutex + drain gate ----

class CardMutex:
    """Per-card mutation mutex (Metis a). Different cards never block each other."""

    def __init__(self):
        self._cond = threading.Condition()
        self._held: dict[str, str] = {}  # card -> holder lane name

    def acquire(self, card: str, who: str, timeout: Optional[float] = None) -> bool:
        with self._cond:
            if not self._cond.wait_for(lambda: card not in self._held, timeout):
                return False
            self._held[card] = who
            return True

    def release(self, card: str) -> None:
        with self._cond:
            self._held.pop(card, None)
            self._cond.notify_all()

    def holder(self, card: str) -> Optional[str]:
        with self._cond:
            return self._held.get(card)

    @contextlib.contextmanager
    def hold(self, card: str, who: str, timeout: Optional[float] = None):
        if not self.acquire(card, who, timeout):
            raise MutationWindowClosed(card, reason="card lock timeout")
        try:
            yield card
        finally:
            self.release(card)


class WindowController:
    """Closes a window's mutation gate at drain time (Metis b)."""

    def __init__(self):
        self._closed = threading.Event()
        self.closed_at: Optional[float] = None
        self.reason = ""

    def close(self, reason: str = "") -> None:
        self.closed_at = time.monotonic()
        self.reason = reason
        self._closed.set()

    def mutation_allowed(self) -> bool:
        return not self._closed.is_set()


# ------------------------------------------------------------ lanes ----

@dataclass
class LaneSpec:
    name: str
    target: Callable[["PhaseContext"], None]
    window: str = "window1"  # window1 | window2 | all_night
    cards: tuple = ()
    needs_pcscd: bool = False
    pace_s: float = 1.0


class LaneHandle:
    def __init__(self, spec: LaneSpec):
        self.spec = spec
        self.stop = threading.Event()
        self.pause = threading.Event()
        self.paused_ack = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.crash: Optional[str] = None

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()


def make_context(*, name: str, store: ResultsStore, clock, mutex: CardMutex,
                 controller: Optional[WindowController] = None,
                 stop_event: threading.Event, pause_event: threading.Event,
                 paused_ack_event: threading.Event, phase_ref: Callable[[], str],
                 cards: tuple = (), pace_s: float = 1.0, dry_run: bool = False,
                 ledger=None, lock_timeout_s: float = 60.0) -> "PhaseContext":
    return PhaseContext(name, store, clock, mutex, controller, stop_event,
                        pause_event, paused_ack_event, phase_ref, cards, pace_s,
                        dry_run, ledger, lock_timeout_s)


class PhaseContext:
    """The lane-facing API (documented in the module docstring)."""

    def __init__(self, name, store, clock, mutex, controller, stop_event, pause_event,
                 paused_ack_event, phase_ref, cards, pace_s, dry_run, ledger,
                 lock_timeout_s):
        self.name, self.store, self.clock = name, store, clock
        self.mutex, self.controller = mutex, controller
        self._stop, self._pause, self._paused_ack = stop_event, pause_event, paused_ack_event
        self._phase_ref, self._lock_timeout = phase_ref, lock_timeout_s
        self.cards, self.pace_s, self.dry_run, self.ledger = cards, pace_s, dry_run, ledger

    @property
    def phase(self) -> str:
        return self._phase_ref()

    def running(self) -> bool:
        return not self._stop.is_set()

    def paused(self) -> bool:
        return self._pause.is_set()

    def sleep(self, s: float) -> None:
        end = self.clock.monotonic() + max(0.0, s)
        while self.running():
            if self.paused():
                self._paused_ack.set()
                while self.paused() and self.running():
                    self.clock.sleep(0.05)
                self._paused_ack.clear()
            rem = end - self.clock.monotonic()
            if rem <= 0:
                return
            self.clock.sleep(min(rem, 0.25))

    def card(self, card_id: str):
        if self.controller is not None and not self.controller.mutation_allowed():
            raise MutationWindowClosed(card_id, reason=self.controller.reason or "drain")
        timeout = self._lock_timeout
        if self.controller is not None:
            timeout = min(timeout, 5.0)
        return self.mutex.hold(card_id, self.name, timeout=timeout)

    # -- persistence helpers -------------------------------------------------
    def row(self, **fields) -> dict:
        fields.setdefault("lane", self.name)
        fields.setdefault("phase", self._phase_ref())
        return self.store.row(**fields)

    def skip(self, reason: str, **fields) -> dict:
        return self.row(type="SKIP", status="SKIP", reason=reason, **fields)

    def anomaly(self, kind: str, **fields) -> dict:
        return self.store.anomaly(kind, lane=self.name, phase=self._phase_ref(), **fields)

    def event(self, kind: str, **fields) -> dict:
        return self.store.event(kind, lane=self.name, phase=self._phase_ref(), **fields)


class LaneRegistry:
    def __init__(self, store: ResultsStore, clock):
        self.store, self.clock = store, clock
        self._lanes: dict[str, LaneHandle] = {}
        self._guard = threading.Lock()

    def start(self, spec: LaneSpec, controller: Optional[WindowController] = None,
              phase_ref: Callable[[], str] = lambda: "", mutex: CardMutex = None,
              ledger=None) -> LaneHandle:
        handle = LaneHandle(spec)
        ctx = make_context(name=spec.name, store=self.store, clock=self.clock,
                           mutex=mutex or CardMutex(), controller=controller,
                           stop_event=handle.stop, pause_event=handle.pause,
                           paused_ack_event=handle.paused_ack, phase_ref=phase_ref,
                           cards=tuple(spec.cards), pace_s=spec.pace_s,
                           ledger=ledger)

        def runner():
            try:
                spec.target(ctx)
            except Exception as e:  # noqa: BLE001 — a crashing track never kills the night
                handle.crash = repr(e)
                self.store.anomaly("lane_crash", lane=spec.name, error=repr(e),
                                   phase=phase_ref())

        handle.thread = threading.Thread(target=runner, name=spec.name, daemon=True)
        with self._guard:
            self._lanes[spec.name] = handle
        handle.thread.start()
        return handle

    def stop_lane(self, handle: LaneHandle, grace_s: float) -> bool:
        handle.stop.set()
        handle.pause.set()  # wake a lane stuck in pause-aware sleep
        if handle.thread is not None:
            handle.thread.join(timeout=max(0.05, grace_s))
        return not handle.alive()

    def stop_all(self, grace_s: float) -> None:
        for h in list(self._handles()):
            self.stop_lane(h, grace_s)

    def pause_pcscd_lanes(self) -> list:
        return [h for h in self._handles() if h.spec.needs_pcscd and h.alive()]

    def lane(self, name: str) -> Optional[LaneHandle]:
        return self._lanes.get(name)

    def _handles(self) -> list:
        with self._guard:
            return list(self._lanes.values())


class PcscdMaintenanceLock:
    """Global pcscd-maintenance lock (Metis f): pauses EVERY needs_pcscd lane
    (Track B and Track D soak alike) around pcscd stop/restart."""

    def __init__(self, registry: LaneRegistry, store: ResultsStore, clock,
                 pause_grace_s: float):
        self.registry, self.store, self.clock = registry, store, clock
        self.grace = float(pause_grace_s)
        self._busy = threading.Lock()

    @contextlib.contextmanager
    def hold(self, who: str):
        with self._busy:
            self.store.event("pcscd_maintenance_begin", who=who)
            lanes = self.registry.pause_pcscd_lanes()
            for h in lanes:
                h.pause.set()
            deadline = self.clock.monotonic() + self.grace
            for h in lanes:
                remaining = deadline - self.clock.monotonic()
                if remaining <= 0 or not h.paused_ack.wait(remaining):
                    self.store.anomaly("pcscd_pause_unacked", lane=h.spec.name, who=who)
            try:
                yield
            finally:
                for h in lanes:
                    h.pause.clear()
                self.store.event("pcscd_maintenance_end", who=who, lanes=[h.spec.name for h in lanes])


def systemctl_pcscd_restart(units: tuple = ("pcscd.socket", "pcscd.service"),
                            settle_s: float = 3.0, retries: int = 1) -> tuple:
    """Default PCSCD_RESTART_REQUEST executor: ``sudo systemctl restart`` with
    one retry (the arming environment has NOPASSWD systemctl — task 1)."""
    last = "no attempt"
    for _ in range(retries + 1):
        try:
            p = subprocess.run(["sudo", "systemctl", "restart", *units],
                               capture_output=True, text=True, timeout=90)
        except (OSError, subprocess.SubprocessError) as e:
            last = repr(e)
            continue
        if p.returncode == 0:
            time.sleep(settle_s)
            return True, "systemctl restart " + " ".join(units)
        last = f"rc={p.returncode} stderr={(p.stderr or '').strip()[:200]}"
    return False, last


# ------------------------------------------------------------- timeline ----

_BUDGET_KEY = {"PREFLIGHT": "preflight_s", "WINDOW1": "window1_s",
               "ROLE_GATE": "role_gate_s", "WINDOW2": "window2_s",
               "RESTORE": "restore_s", "REPORT": "report_s"}


class Timeline:
    """Anchor-fixed schedule (Metis c): each phase's END never moves, so an
    overrun SHRINKS the phase (possibly to zero) instead of delaying REPORT."""

    def __init__(self, cfg: dict, t0_mono: float):
        self.t0 = t0_mono
        self.total = float(cfg["duration_s"])
        self.ends, t = {}, t0_mono
        for name in PHASES:
            t += float(cfg["phases"][_BUDGET_KEY[name]])
            self.ends[name] = t
        if abs(t - (t0_mono + self.total)) > 1.0:
            raise ConfigError("phase budgets do not sum to duration")

    def planned_start(self, name: str) -> float:
        i = PHASES.index(name)
        return self.t0 if i == 0 else self.ends[PHASES[i - 1]]

    def anchor_end(self, name: str) -> float:
        return self.ends[name]

    def actual_window(self, name: str, now: float) -> tuple:
        """(start, end, duration) given the current time — never extends the anchor."""
        start = max(now, self.planned_start(name))
        end = self.anchor_end(name)
        return start, end, max(0.0, end - start)

    @property
    def hard_end(self) -> float:
        return self.ends[PHASES[-1]]


# -------------------------------------------------------------- report ----

def build_report_md(state: dict) -> str:
    """Render report.md from a results.json state dict (pure; watchdog-safe)."""
    run = state.get("run", {})
    phases = state.get("phases", [])
    rows = state.get("rows", [])
    timeline = state.get("timeline", [])
    out: list[str] = []
    a = out.append
    a("# Overnight HIL Audit Report")
    a("")
    a(f"- Started: {run.get('started_at')}")
    a(f"- Ended: {run.get('ended_at')}")
    a(f"- Status: {run.get('status')} (exit_code={run.get('exit_code')})")
    a(f"- Dry run: {'yes' if run.get('dry_run') else 'no'}")
    md = state.get("mode_decision")
    a(f"- Mode: {md.get('mode', 'undecided') if md else 'undecided'}")
    a("")
    a("## Mode Decision")
    a("")
    if md:
        for k, v in md.items():
            a(f"- **{k}**: {v}")
    else:
        a("- (no mode decision recorded — run died before the role gate)")
    a("")
    for name in PHASES:
        entries = [p for p in phases if p["name"] == name]
        p = entries[-1] if entries else {"name": name, "status": "not reached",
                                         "planned_dur_s": None, "actual_dur_s": None,
                                         "detail": ""}
        a(f"## Phase: {name}")
        a("")
        a(f"- status: {p.get('status')}  |  planned: {p.get('planned_dur_s')}s"
          f"  |  detail: {p.get('detail') or '-'}")
        prows = [r for r in rows if r.get("phase") == name]
        if prows:
            a("")
            a("| ts | lane | type | status | detail |")
            a("|---|---|---|---|---|")
            for r in prows[-60:]:
                extra = {k: v for k, v in r.items()
                         if k not in ("ts", "lane", "type", "status", "phase", "mono")}
                a(f"| {r.get('ts', '')} | {r.get('lane') or '-'} | {r.get('type')} "
                  f"| {r.get('status')} | {json.dumps(extra, default=str)[:160]} |")
            if len(prows) > 60:
                a(f"\n_(showing last 60 of {len(prows)} rows; full data in results.json)_")
        a("")
    a("## Anomaly Timeline")
    a("")
    anomalies = [e for e in timeline if e.get("level") == "anomaly"]
    if not anomalies:
        a("_none_")
    for e in anomalies:
        extra = {k: v for k, v in e.items() if k not in ("level", "kind", "ts")}
        a(f"- `{e['ts']}` **{e['kind']}** {json.dumps(extra, default=str)[:200]}")
    a("")
    a("## SKIP Log")
    a("")
    skips = [r for r in rows if r.get("status") == "SKIP"]
    if not skips:
        a("_none_")
    for r in skips:
        a(f"- `{r.get('ts')}` [{r.get('lane') or r.get('item') or '-'}] "
          f"{r.get('reason', '(no reason given)')}")
    a("")
    a("---")
    a("_Full data: results.json (incremental, atomic). Report rebuilt from it by "
      "`build_report_md(ResultsStore.load(...))`._")
    return "\n".join(out) + "\n"


# --------------------------------------------------------- orchestrator ----

class Orchestrator:
    def __init__(self, cfg: dict, store: ResultsStore, clock, *, specs: list,
                 role_gate: Callable, restore_fn: Callable, preflight_fn: Callable,
                 probes: dict, monitor_factory: Optional[Callable[[], ConsoleMonitor]] = None,
                 dry_run: bool = False, ledger=None,
                 pcscd_restart_fn: Optional[Callable[[], tuple]] = None):
        self.cfg, self.store, self.clock = cfg, store, clock
        self.mutex = CardMutex()
        self.registry = LaneRegistry(store, clock)
        self.pcscd = PcscdMaintenanceLock(self.registry, store, clock,
                                          cfg["pcscd_pause_grace_s"])
        self.specs, self.probes = list(specs), dict(probes)
        self.role_gate, self.restore_fn = role_gate, restore_fn
        self.preflight_fn, self.monitor_factory = preflight_fn, monitor_factory
        self.dry_run, self.ledger = dry_run, ledger
        self.pcscd_restart_fn = pcscd_restart_fn or systemctl_pcscd_restart
        self.timeline: Optional[Timeline] = None
        self._phase = ["PREFLIGHT"]
        self._monitor: Optional[ConsoleMonitor] = None
        self._hb = Heartbeat(store, clock, store.dir / "heartbeat.json",
                             cfg["heartbeat_interval_s"])
        self._abort_requested = threading.Event()
        self._abort_stopped_lanes = False
        self._gate_ran = False

    # -- helpers -------------------------------------------------------------
    def _phase_name(self) -> str:
        return self._phase[0]

    def _gate_ctx(self, name: str) -> PhaseContext:
        stop = threading.Event()
        return make_context(name=name, store=self.store, clock=self.clock,
                            mutex=self.mutex, controller=None, stop_event=stop,
                            pause_event=threading.Event(), paused_ack_event=threading.Event(),
                            phase_ref=self._phase_name, ledger=self.ledger,
                            dry_run=self.dry_run)

    def _wait_until(self, t: float) -> None:
        while self.clock.monotonic() < t:
            self._hb.maybe_write(self._phase_name())
            self._poll_cross_process()
            if self._abort_requested.is_set():
                return  # cut the wait short; drain still runs (req. h)
            self.clock.sleep(min(0.25, max(0.001, t - self.clock.monotonic())))

    # -- cross-process coordination (req. f/h) ---------------------------------
    def _poll_cross_process(self) -> None:
        """Main-loop poll alongside heartbeat maintenance: the operator ABORT
        file (graceful wind-down at the next phase boundary) and the todo-16
        watchdog's PCSCD_RESTART_REQUEST marker."""
        if not self._abort_requested.is_set() and \
                (self.store.dir / ABORT_FILENAME).exists():
            self._abort_requested.set()
            self.store.event("abort_requested", phase=self._phase_name(),
                             path=str(self.store.dir / ABORT_FILENAME))
            self.store.row(type="abort", status="ABORT", phase=self._phase_name(),
                           reason="operator ABORT file detected — winding down at "
                                  "the next phase boundary (in-flight ops drain "
                                  "first)")
        self._service_pcscd_marker()

    def _service_pcscd_marker(self) -> None:
        """Execute a watchdog PCSCD_RESTART_REQUEST UNDER the global
        pcscd-maintenance lock, then atomically CONSUME it — rename to
        ``<marker>.done`` then delete — so a serviced request can never
        re-execute on a later poll (oracle r3)."""
        marker = self.store.dir / PCSCD_RESTART_MARKER
        if not marker.exists():
            return
        self.store.event("pcscd_restart_request_seen", phase=self._phase_name())
        try:
            with self.pcscd.hold("watchdog_request"):
                ok, detail = self.pcscd_restart_fn()
            done = marker.with_name(marker.name + ".done")
            try:
                os.replace(marker, done)  # atomic consume: marker path gone
                done.unlink(missing_ok=True)
            except FileNotFoundError:
                pass  # watchdog retracted it (reader recovered mid-service)
            if ok:
                self.store.event("pcscd_restart_request_serviced", detail=detail)
            else:
                self.store.anomaly("pcscd_restart_request_failed", detail=detail)
        except Exception as e:  # noqa: BLE001 — marker servicing never kills the night
            self.store.anomaly("pcscd_restart_request_error", error=repr(e))

    def _specs_for(self, window: str) -> list:
        return [s for s in self.specs if s.window == window]

    def _skip_missing_tracks(self, window: str) -> None:
        key = {"window1": "window1_tracks", "window2": "window2_ccid_tracks",
               "all_night": "all_night_tracks"}[window]
        have = {s.name for s in self._specs_for(window)}
        for name in self.cfg.get(key, []):
            if name not in have:
                self.store.row(type="SKIP", status="SKIP", phase=self._phase_name(),
                               lane=name, reason="track module not implemented yet "
                               "(todos 7-16) — honest degradation")

    def _start_lanes(self, specs: list, controller: Optional[WindowController]) -> list:
        handles = []
        for spec in specs:
            handles.append(self.registry.start(
                spec, controller=controller, phase_ref=self._phase_name,
                mutex=self.mutex, ledger=self.ledger))
        return handles

    def _monitor_set(self, active: bool) -> None:
        """Run the console monitor exactly while the bolty role is live."""
        if self._monitor is None:
            return
        if active and self._monitor._thread is None:
            self._monitor.start()
        elif not active and self._monitor._thread is not None:
            self._monitor.stop()

    # -- drain (Metis b) -------------------------------------------------------
    def drain(self, phase: str, lanes: list, cards: list,
              controller: WindowController) -> bool:
        """Close the mutation window, wait <=drain_grace_s for in-flight card
        operations BY THIS WINDOW'S LANES to clear (all-night lanes such as
        Track B may legally keep mutating), then record card-state rows."""
        controller.close(f"{phase} drain at T-{self.cfg['drain_lead_s']:.0f}s")
        self.store.event("drain_begin", phase=phase, cards=list(cards))
        window_names = {h.spec.name for h in lanes}

        def _blocked() -> list:
            return [c for c in cards if self.mutex.holder(c) in window_names]

        deadline = self.clock.monotonic() + float(self.cfg["drain_grace_s"])
        clean = True
        while _blocked():
            if self.clock.monotonic() >= deadline:
                held = _blocked()
                self.store.anomaly("drain_grace_elapsed", phase=phase, held=held)
                for h in lanes:
                    h.stop.set()
                for h in lanes:
                    if h.alive() and not self.registry.stop_lane(h, 1.0):
                        self.store.anomaly("lane_force_stop_failed", phase=phase,
                                           lane=h.spec.name)
                for c in held:
                    if self.mutex.holder(c) in window_names:  # abandoned lock
                        self.mutex.release(c)
                        self.store.anomaly("card_lock_abandoned", phase=phase, card=c)
                clean = False
                break
            self.clock.sleep(0.05)
        for card in cards:
            probe = self.probes.get(card)
            try:
                data = probe() if probe else {"card_state": "not_probed",
                                              "reason": "no probe registered"}
            except Exception as e:  # a failing probe is a recorded row, never a crash
                self.store.row(type="card_state", status="ERROR", phase=phase, card=card,
                               error=repr(e))
                clean = False
                continue
            self.store.row(type="card_state", status="PASS", phase=phase, card=card, **data)
        self.store.event("drain_complete", phase=phase, clean=clean)
        return clean

    # -- phases ----------------------------------------------------------------
    def _run_window(self, name: str, cards: list, mode_b: bool) -> None:
        controller = WindowController()
        if mode_b:
            self._skip_missing_tracks("window2")
            for t in self.cfg.get("window2_ccid_tracks", []):
                self.store.row(type="SKIP", status="SKIP", phase=name, lane=t,
                               reason="Mode B fallback: ccid window deferred to night 2")
            handles = []
        else:
            handles = self._start_lanes(self._specs_for("window2"), controller)
        self._monitor_set(mode_b)  # in Mode B the bolty role lives through window 2
        start, end, dur = self.timeline.actual_window(name, self.clock.monotonic())
        self._wait_until(end - self.cfg["drain_lead_s"])
        self.drain(name, handles, cards, controller)
        for h in handles:
            if h.alive() and not self.registry.stop_lane(h, self.cfg["lane_join_s"]):
                self.store.row(type="SKIP", status="SKIP", phase=name, lane=h.spec.name,
                               reason="window overrun: bounded-iteration grace elapsed; "
                                      "remaining iterations skipped")

    def run(self) -> int:
        cfg = self.cfg
        self.store.mark_started(dry_run=self.dry_run)
        self.timeline = Timeline(cfg, self.clock.monotonic())
        self._hb.maybe_write("PREFLIGHT", force=True)
        self._hb.start_writer(self._phase_name)  # req. g: thread-independent hb
        mode_b, preflight_ok = False, True
        try:
            for phase in PHASES:
                self._phase[0] = phase
                self._poll_cross_process()
                if self._abort_requested.is_set() and phase not in ("RESTORE", "REPORT"):
                    if not self._abort_stopped_lanes:  # wind down all lanes once
                        self._abort_stopped_lanes = True
                        self.registry.stop_all(min(cfg["lane_join_s"], 2.0))
                    self.store.begin_phase(phase, 0.0)
                    self.store.end_phase(phase, "skipped", "operator ABORT — "
                                         "graceful wind-down")
                    self.store.row(type="SKIP", status="SKIP", phase=phase,
                                   reason="operator ABORT (ABORT file) — phase "
                                          "skipped; lanes wound down at the prior "
                                          "boundary")
                    continue
                now = self.clock.monotonic()
                start, end, dur = self.timeline.actual_window(phase, now)
                self._hb.maybe_write(phase, force=True)
                if dur <= 0 and phase != "REPORT":
                    self.store.begin_phase(phase, 0.0)
                    self.store.end_phase(phase, "skipped",
                                         "prior phase overrun consumed the budget")
                    self.store.row(type="SKIP", status="SKIP", phase=phase,
                                   reason="phase budget consumed by earlier overrun "
                                          "(dynamic shrink, Metis c)")
                    continue
                self.store.begin_phase(phase, max(0.0, self.timeline.ends[phase] - start))

                if phase == "PREFLIGHT":
                    preflight_ok = bool(self.preflight_fn(self._gate_ctx("preflight")))
                    self._wait_until(end)
                    if preflight_ok:
                        self.store.end_phase(phase, "completed")
                    else:
                        self.store.set_mode({"mode": "aborted — preflight failed",
                                             "ok": False,
                                             "decided_at": _iso(self.clock.time())})
                        self.store.end_phase(phase, "failed",
                                             "preflight failed — winding down safely "
                                             "(no lanes started)")
                elif phase == "WINDOW1":
                    if not preflight_ok:
                        self.store.end_phase(phase, "skipped", "preflight failed")
                        continue
                    if self.monitor_factory is not None:
                        self._monitor = self.monitor_factory()
                    self._skip_missing_tracks("window1")
                    self._skip_missing_tracks("all_night")
                    self._start_lanes(self._specs_for("all_night"), None)
                    controller = WindowController()
                    handles = self._start_lanes(self._specs_for("window1"), controller)
                    self._monitor_set(True)
                    _, end2, _ = self.timeline.actual_window(phase, self.clock.monotonic())
                    self._wait_until(end2 - cfg["drain_lead_s"])
                    self.drain(phase, handles, list(cfg["cards"]), controller)
                    self._monitor_set(False)  # leaving the bolty role
                    for h in handles:
                        if h.alive() and not self.registry.stop_lane(h, cfg["lane_join_s"]):
                            self.store.row(type="SKIP", status="SKIP", phase=phase,
                                           lane=h.spec.name,
                                           reason="window overrun: bounded-iteration "
                                                  "grace elapsed; remaining iterations skipped")
                    self.store.end_phase(phase, "completed",
                                         "operator ABORT — window cut short at drain"
                                         if self._abort_requested.is_set() else "")
                elif phase == "ROLE_GATE":
                    if not preflight_ok:
                        self.store.end_phase(phase, "skipped", "preflight failed")
                        continue
                    self._gate_ran = True
                    with self.pcscd.hold("role_gate"):
                        res = self.role_gate(self._gate_ctx("role_gate"))
                    if res.ok:
                        decision = {"mode": "Mode A — dual-role single night",
                                    "ok": True, "detail": res.detail,
                                    "decided_at": _iso(self.clock.time())}
                        mode_b = False
                    else:
                        with self.pcscd.hold("role_gate_restore"):
                            rres = self.restore_fn(self._gate_ctx("role_gate_restore"))
                        mode_b = True
                        decision = {"mode": "Mode B — role switch failed; ccid deferred "
                                            "to night 2 (fallback)",
                                    "ok": False, "detail": f"gate: {res.detail}; "
                                    f"restore: {rres.detail}",
                                    "decided_at": _iso(self.clock.time())}
                        self.store.anomaly("role_gate_failed", detail=res.detail)
                    self.store.set_mode(decision)
                    self.store.end_phase(phase, "completed")
                elif phase == "WINDOW2":
                    if not preflight_ok:
                        self.store.end_phase(phase, "skipped", "preflight failed")
                        continue
                    self._run_window(phase, list(cfg["cards"]), mode_b)
                    self.store.end_phase(phase, "completed" if not mode_b else
                                         "completed (Mode B degraded)",
                                         "operator ABORT — window cut short at drain"
                                         if self._abort_requested.is_set() else "")
                elif phase == "RESTORE":
                    if not preflight_ok:
                        self.store.end_phase(phase, "skipped", "preflight failed")
                        continue
                    if self._abort_requested.is_set() and not self._gate_ran:
                        self.store.event("restore_skipped_abort",
                                         detail="ABORT before the role gate — device "
                                                "never left the bolty role")
                        self.store.end_phase(phase, "skipped",
                                             "operator ABORT before role gate — "
                                             "nothing to restore")
                        continue
                    self._monitor_set(True)  # bolty role is live again (both modes)
                    if mode_b:
                        self.store.event("restore_skipped_mode_b",
                                         detail="already restored at gate failure")
                        self.store.end_phase(phase, "completed",
                                             "Mode B: device already restored to bolty")
                    else:
                        with self.pcscd.hold("restore"):
                            res = self.restore_fn(self._gate_ctx("restore"))
                        if not res.ok:
                            self.store.anomaly("restore_failed", detail=res.detail)
                        self.store.end_phase(phase,
                                              "completed" if res.ok else "degraded",
                                              res.detail)
                    self._monitor_set(False)
                elif phase == "REPORT":
                    if dur <= 0:
                        self.store.row(type="SKIP", status="SKIP", phase=phase,
                                       reason="report budget consumed by earlier overrun "
                                              "(built immediately; Metis c)")
                    self._write_report()
                    self.store.end_phase(phase, "completed")
                # regenerate report.md at every phase boundary (dead-scheduler view)
                if phase != "REPORT":
                    self._write_report()
                self._hb.maybe_write(phase, force=True)
            self.registry.stop_all(min(cfg["lane_join_s"], 2.0))
            self.store.finish(0, "aborted (operator ABORT)"
                              if self._abort_requested.is_set() else "completed")
            self._write_report()
            return 0
        except Exception as e:  # noqa: BLE001 — catastrophic: record + partial report
            self.store.anomaly("scheduler_fatal", error=repr(e))
            self.store.finish(3, "fatal")
            try:
                self._write_report()
            except Exception as e2:  # last-resort: say it loudly, never silently
                print(f"[overnight] report write failed after fatal error: {e2!r}",
                      file=sys.stderr)
            return 3
        finally:
            self._hb.stop_writer()  # a dead scheduler must stop heartbeating

    def _write_report(self) -> Path:
        md = build_report_md(self.store.state)
        tmp = self.store.report_path.with_name("report.md.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(md)
        os.replace(tmp, self.store.report_path)
        return self.store.report_path


# ------------------------------------------------------- probes (real HW) ----

def console_inspect_probe(socket_path: str = "/run/bolty/console.sock",
                          timeout: float = 15.0) -> dict:
    """Stick-card state via the bolty-console daemon (`inspect`). Read-only."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(socket_path)
    s.sendall(b"inspect\n")
    out = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        out += c
    s.close()
    text = out.decode("latin1", "replace")
    if not text.splitlines() or not text.splitlines()[-1].startswith("OK"):
        raise RuntimeError(f"console inspect failed: {text!r}")
    low = text.lower()
    state = "provisioned" if "provisioned" in low else \
            "blank" if "blank" in low else "unknown"
    return {"card_state": state, "raw_tail": text.strip()[-200:]}


# --------------------------------------------------- tolerant integrations ----

def try_load_ledger(results_dir=None):
    """Todo-6 ledger is optional at import time; None means 'not landed yet'."""
    try:
        import ledger  # noqa: F401  (same directory, todo 6)
        return ledger
    except ImportError:
        return None


def load_track_specs(cfg: dict, sink: Optional[Callable] = None) -> list:
    """Tolerantly import track modules (todos 7-14). Each provides
    build_lane() -> LaneSpec. Missing modules contribute no specs (the
    orchestrator emits honest SKIP rows from the config track lists); broken
    modules get a recorded ERROR row via `sink`."""
    specs = []
    for mod_name in ("track_a", "track_b", "track_c", "track_d"):
        try:
            mod = __import__(mod_name)
        except ImportError:
            continue
        try:
            spec = mod.build_lane()
            if isinstance(spec, LaneSpec):
                specs.append(spec)
        except Exception as e:  # noqa: BLE001 — module present but broken: record it
            if sink is not None:
                sink(type="ERROR", status="ERROR", lane=mod_name,
                     error=f"build_lane failed: {e!r}")
    return specs


# ------------------------------------------------------------ dry-run app ----

class ScriptedPing:
    """Deterministic fake daemon PING for dry-runs (incl. one hb_gap episode)."""

    def __init__(self):
        self.i = 0
        self.reset()

    def reset(self) -> None:
        self.t = 10_000

    def __call__(self) -> dict:
        self.i += 1
        self.t += 10_000
        age = 45 if self.i == 5 else 5  # one scripted gap episode
        line = f"[HB] alive t={self.t}ms nfc=ok"
        return {"hb_age": age, "lines": [line], "error": None}


def _dry_mutating_track(ctx: PhaseContext, hold_s: float = 0.0) -> None:
    n = 0
    while ctx.running():
        if n >= 4:
            ctx.event("dry_lane_done", planned=4)
            return
        card = ctx.cards[0] if ctx.cards else None
        try:
            if card:
                with ctx.card(card):
                    if hold_s:
                        ctx.clock.sleep(hold_s)
                    ctx.row(type="mutation", status="PASS", i=n, card=card)
            else:
                ctx.row(type="poll", status="PASS", i=n)
        except MutationWindowClosed:
            ctx.skip("mutation window closed (drain)")
            return
        n += 1
        ctx.sleep(ctx.pace_s)


def _dry_poll_track(ctx: PhaseContext) -> None:
    _dry_mutating_track(ctx)


def _dry_preflight(ctx: PhaseContext) -> bool:
    for check in ("console PING", "pcscd readers", "prebuilt images manifest"):
        ctx.row(type="preflight", status="PASS", check=f"simulated {check}")
    return True


def build_dry_run_app(cfg: dict, out_dir: str | Path, gate_ok: bool,
                      extra_specs: list = ()) -> Orchestrator:
    store = ResultsStore(out_dir)
    clock = RealClock()
    ping = ScriptedPing()
    base = dict(pace_s=max(cfg.get("pace_s", 0.05), DRY_FLOORS["pace_s"]))

    def mk(name, window, cards=(), needs_pcscd=False, hold_s=0.0):
        return LaneSpec(name, lambda ctx, h=hold_s: _dry_mutating_track(ctx, h),
                        window=window, cards=cards, needs_pcscd=needs_pcscd, **base)

    specs = [
        mk("track_a_cycles", "window1", cards=("stick",)),
        mk("track_a_rest", "window1", cards=("stick",)),
        mk("track_b_acr", "all_night", cards=("acr",), needs_pcscd=True),
        LaneSpec("track_c_host", _dry_poll_track, window="all_night", **base),
        mk("track_d_soak", "window2", cards=("acr",), needs_pcscd=True),
    ] + list(extra_specs)

    def gate(ctx):
        return GateResult(ok=gate_ok,
                          detail="simulated role switch " + ("ok" if gate_ok else "FAILED"))

    def restore(ctx):
        ping.reset()  # reflash -> reboot -> uptime regression is expected
        return GateResult(ok=True, detail="simulated restore ok")

    def monitor_factory():
        return ConsoleMonitor(sink=lambda ev: store.anomaly(**ev), clock=clock,
                              max_age_s=cfg["hb"]["max_age_s"],
                              poll_s=cfg["hb"]["poll_s"], ping=ping, log_path=None)

    probes = {"stick": lambda: {"card_state": "blank (simulated)"},
              "acr": lambda: {"card_state": "provisioned (simulated)"}}
    return Orchestrator(cfg, store, clock, specs=specs, role_gate=gate,
                        restore_fn=restore, preflight_fn=_dry_preflight,
                        probes=probes, monitor_factory=monitor_factory, dry_run=True,
                        ledger=try_load_ledger(),
                        pcscd_restart_fn=lambda: (True, "simulated (dry-run) "
                                                        "pcscd restart"))


# ----------------------------------------------------------------- CLI ----

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Overnight dual-role HIL orchestrator "
                                             "(todo 5 core)")
    ap.add_argument("--config", help="config JSON (required for real runs)")
    ap.add_argument("--dry-run", action="store_true",
                    help="no hardware; compressed simulated timeline")
    ap.add_argument("--start", help="ISO start time (real runs; waits until then)")
    ap.add_argument("--duration", type=float,
                    help="override total duration_s (compresses budgets proportionally)")
    ap.add_argument("--gate", choices=("ok", "fail"),
                    help="dry-run role-gate injection (default: fail -> Mode B path)")
    ap.add_argument("--results-dir", help="override config results dir")
    args = ap.parse_args(argv)

    gate_env = os.environ.get("OVERNIGHT_INJECT_ROLE_GATE")
    gate_ok = (args.gate or gate_env or ("fail" if args.dry_run else "ok")) == "ok"

    if args.dry_run:
        cfg = merge_defaults(load_config(args.config)) if args.config else merge_defaults({})
        total = args.duration or cfg.get("dry_run_total_s", DRY_TOTAL_S)
        cfg = scale_config(cfg, min(total, 120.0), dry=True)
        out = Path(args.results_dir) if args.results_dir else \
            Path(__file__).resolve().parent / "results" / "dry-run"
        orch = build_dry_run_app(cfg, out, gate_ok=gate_ok)
    else:
        if not args.config:
            print("error: --config is required for real runs (or use --dry-run)",
                  file=sys.stderr)
            return 2
        cfg = load_config(args.config)
        if args.duration:
            cfg = scale_config(cfg, args.duration, dry=False)
        out = Path(args.results_dir or cfg.get("results_dir") or
                   (Path(__file__).resolve().parent / "results" / "run"))
        ledger = try_load_ledger()
        store = ResultsStore(out)
        specs = load_track_specs(cfg, sink=store.row)

        def gate(ctx):
            try:
                import role_switch  # todo 15
                return role_switch.switch_to("ccid", ctx)
            except ImportError as e:
                return GateResult(ok=False, detail=f"role_switch not implemented "
                                                   f"(todo 15): {e}")

        def restore(ctx):
            try:
                import role_switch
                return role_switch.switch_to("bolty", ctx)
            except ImportError as e:
                return GateResult(ok=False, detail=f"role_switch not implemented: {e}")

        def preflight(ctx):
            ctx.skip("real preflight implemented by todo 18 (rehearsal arming)")
            return True  # proceed with whatever tracks ARE available

        store = ResultsStore(out)
        probes = {"stick": console_inspect_probe}
        orch = Orchestrator(cfg, store, RealClock(), specs=specs, role_gate=gate,
                            restore_fn=restore, preflight_fn=preflight, probes=probes,
                            monitor_factory=lambda: ConsoleMonitor(
                                sink=lambda ev: store.anomaly(**ev), clock=RealClock(),
                                max_age_s=cfg["hb"]["max_age_s"],
                                poll_s=cfg["hb"]["poll_s"],
                                ping=lambda: ping_daemon(cfg["hb"]["console_socket"]),
                                log_path=cfg["hb"]["console_log"]),
                            ledger=ledger)

    rc = orch.run()
    print(f"report: {orch.store.report_path}")
    print(f"results: {orch.store.path} (exit {rc})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
