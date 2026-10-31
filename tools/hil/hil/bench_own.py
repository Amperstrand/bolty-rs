"""Bench ownership for standalone HIL scripts (#234).

pytest suites get conftest's rig_lock; standalone scripts
(h1_burn_regression.py) got NOTHING — burn/wipe cycles could race any
other holder of the ACR, interrupting key changes mid-mutation. This is
the script-side twin of the rig_lock doctrine, same order discipline:

  1. tollgate-lab BenchLock FIRST (cross-project kernel flock)
  2. labgrid place acquisition second (network-visible exclusivity)

Release happens in reverse order on EVERY exit path (call .release() in
a finally). A hardware run that cannot take ownership FAILS CLOSED —
never degrade to lockless (the #199 collision class).

Env knobs:
  H1_SKIP_BENCH_LOCK=1   explicit smoke-mode opt-out (stubbed
                         BOLTY_CLI_BIN + H1_SKIP_PROBE runs only)
  BOLTY_LG_PLACE         labgrid place (default ref-acr1252-small —
                         the ACR leaf on ai-legion-small, #127 pattern)
  BOLTY_LG_COORDINATOR   coordinator address (default 192.168.13.208:20408)
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PLACE = "ref-acr1252-small"
DEFAULT_COORDINATOR = "192.168.13.208:20408"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class BenchOwnershipError(RuntimeError):
    """Ownership could not be taken — the run must not proceed."""


@dataclass
class BenchOwnership:
    """Holds taken locks; release() unwinds in reverse acquisition order."""

    place: str | None = None
    place_inherited: bool = False
    bench_lock: object | None = None
    log: object = print  # injected in tests
    # #209 review: prior BOLTY_SKIP_BENCH_LOCK value (None = was unset).
    # The child bypass is scoped to the ownership lifetime; release()
    # restores it so a later BoltyCli in this same process cannot bypass
    # the gate after we no longer hold the flock.
    skip_saved: str | None = None
    skip_armed: bool = field(default=False, repr=False)
    _released: bool = field(default=False, repr=False)

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        if self.skip_armed:
            self.skip_armed = False
            if self.skip_saved is None:
                os.environ.pop("BOLTY_SKIP_BENCH_LOCK", None)
            else:
                os.environ["BOLTY_SKIP_BENCH_LOCK"] = self.skip_saved
        # reverse order (AB-BA): place first, then the bench flock
        if self.place and not self.place_inherited:
            try:
                _lg_client(self.place, "release")
                self.log(f"bench-own: released labgrid place {self.place}")
            except Exception as exc:  # noqa: BLE001 — release is best-effort
                self.log(f"bench-own: place release FAILED ({exc}) — run labgrid-client -p {self.place} release manually")
        if self.bench_lock is not None:
            try:
                self.bench_lock.release()
                self.log("bench-own: released BenchLock")
            except Exception as exc:  # noqa: BLE001
                self.log(f"bench-own: BenchLock release FAILED ({exc})")


def _lg_client(place: str, *args: str, timeout_s: float = 20):
    coordinator = os.environ.get("BOLTY_LG_COORDINATOR", DEFAULT_COORDINATOR)
    return subprocess.run(
        ["labgrid-client", "-x", coordinator, "-p", place, *args],
        capture_output=True, text=True, timeout=timeout_s,
    )


def _sign_identity() -> None:
    """Bench canon: every hold is signed so `labgrid-client who` answers
    who-and-why. Only fills the unset case (LG_USERNAME wins)."""
    if os.environ.get("LG_USERNAME"):
        return
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=10, cwd=REPO_ROOT,
        ).stdout.strip()
    except Exception:
        sha = "nogit"
    os.environ["LG_USERNAME"] = f"h1-burn-regression~sha={sha}"


def acquire_bench_ownership(
    place: str | None = None,
    log=print,  # noqa: E702
) -> BenchOwnership:
    """Take BenchLock + labgrid place. Raises BenchOwnershipError — the
    caller fails closed and must not touch hardware."""
    own = BenchOwnership(log=log)
    place = place or os.environ.get("BOLTY_LG_PLACE", DEFAULT_PLACE)
    own.place = place

    # 1. tollgate-lab BenchLock (cross-project flock) — FIRST
    try:
        from tollgate_lab import BenchLockHeldError, acquire_bench_lock
    except ImportError as exc:
        raise BenchOwnershipError(
            "tollgate-lab not importable on this host — a hardware run "
            "cannot start without the bench flock (install tollgate-lab "
            "or set H1_SKIP_BENCH_LOCK=1 for stubbed smoke runs)"
        ) from exc
    try:
        own.bench_lock = acquire_bench_lock(
            name="amperstrand-bench", timeout_s=0.0, project="bolty-rs"
        )
    except BenchLockHeldError as exc:
        raise BenchOwnershipError(f"BenchLock held by another session: {exc}") from exc
    log(f"bench-own: BenchLock taken (place {place} next)")
    # #209: bolty-cli children take this same flock themselves on
    # physical-reader connects; export the child-skip so they don't
    # refuse against their own parent (flock is per-fd). Scoped to the
    # ownership lifetime — release() restores the prior value.
    own.skip_saved = os.environ.get("BOLTY_SKIP_BENCH_LOCK")
    os.environ.setdefault("BOLTY_SKIP_BENCH_LOCK", "1")
    own.skip_armed = True

    # 2. labgrid place — SECOND (network-visible exclusivity)
    _sign_identity()
    r = _lg_client(place, "acquire")
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()
        # inherited hold (crashed prior run of the same identity): keep
        # exclusivity, but do NOT release what the enclosing session owns
        who = _lg_client(place, "who")
        if os.environ.get("LG_USERNAME", "") in (who.stdout or ""):
            own.place_inherited = True
            log(f"bench-own: place {place} already held by THIS identity — inheriting")
        else:
            own.release()
            raise BenchOwnershipError(
                f"labgrid place {place} unavailable: {err or 'held'}"
            )
    else:
        log(f"bench-own: labgrid place {place} acquired")
    return own


def bench_ownership_skipped() -> bool:
    return os.environ.get("H1_SKIP_BENCH_LOCK") == "1"


def main_smoke() -> int:
    """`python3 -m hil.bench_own` — take ownership for 5 s, then release
    (manual bench-exclusivity probe)."""
    own = acquire_bench_ownership()
    print("held for 5s…", file=sys.stderr)
    import time

    time.sleep(5)
    own.release()
    return 0


if __name__ == "__main__":
    sys.exit(main_smoke())
