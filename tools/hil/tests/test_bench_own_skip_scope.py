"""BOLTY_SKIP_BENCH_LOCK scoping (#248 review follow-up).

The child bypass exported while bench ownership is held must be scoped to
the ownership lifetime: release() (including the failed-place-acquisition
cleanup path inside acquire_bench_ownership) restores the prior value so a
later BoltyCli in the same process cannot bypass the gate once the flock
is no longer held.
"""

import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hil import bench_own  # noqa: E402


class _FakeLock:
    def __init__(self):
        self.released = False

    def release(self):
        self.released = True


def test_release_restores_unset_skip(monkeypatch):
    monkeypatch.delenv("BOLTY_SKIP_BENCH_LOCK", raising=False)
    lock = _FakeLock()
    own = bench_own.BenchOwnership(bench_lock=lock, skip_saved=None, skip_armed=True)
    own.release()
    assert "BOLTY_SKIP_BENCH_LOCK" not in os.environ, "unset prior must be popped"
    assert lock.released


def test_release_restores_prior_value(monkeypatch):
    monkeypatch.setenv("BOLTY_SKIP_BENCH_LOCK", "0")
    lock = _FakeLock()
    own = bench_own.BenchOwnership(bench_lock=lock, skip_saved="0", skip_armed=True)
    own.release()
    assert os.environ["BOLTY_SKIP_BENCH_LOCK"] == "0", "prior value must be restored"


def test_release_without_arm_leaves_env_untouched(monkeypatch):
    monkeypatch.setenv("BOLTY_SKIP_BENCH_LOCK", "1")
    own = bench_own.BenchOwnership()
    own.release()
    assert os.environ["BOLTY_SKIP_BENCH_LOCK"] == "1"


def test_acquire_arms_and_release_restores(monkeypatch):
    monkeypatch.delenv("BOLTY_SKIP_BENCH_LOCK", raising=False)

    stub = types.ModuleType("tollgate_lab")

    class BenchLockHeldError(Exception):
        pass

    stub.BenchLockHeldError = BenchLockHeldError
    stub.acquire_bench_lock = lambda **kw: _FakeLock()
    monkeypatch.setitem(sys.modules, "tollgate_lab", stub)

    class _R:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(bench_own, "_lg_client", lambda place, *a, **kw: _R())
    monkeypatch.setattr(bench_own, "_sign_identity", lambda: None)

    own = bench_own.acquire_bench_ownership(place="p-scope-test", log=lambda *_: None)
    assert os.environ.get("BOLTY_SKIP_BENCH_LOCK") == "1", "bypass armed under ownership"
    own.release()
    assert "BOLTY_SKIP_BENCH_LOCK" not in os.environ, (
        "bypass must not outlive the ownership"
    )


def test_failed_place_acquisition_still_restores(monkeypatch):
    # The cleanup path inside acquire_bench_ownership calls release();
    # the bypass must be restored there too.
    monkeypatch.delenv("BOLTY_SKIP_BENCH_LOCK", raising=False)

    stub = types.ModuleType("tollgate_lab")

    class BenchLockHeldError(Exception):
        pass

    stub.BenchLockHeldError = BenchLockHeldError
    stub.acquire_bench_lock = lambda **kw: _FakeLock()
    monkeypatch.setitem(sys.modules, "tollgate_lab", stub)

    class _RFail:
        returncode = 1
        stdout = ""
        stderr = "held"

    class _RWho:
        returncode = 0
        stdout = "someone-else"
        stderr = ""

    def _client(place, *args, **kw):
        return _RWho() if args and args[0] == "who" else _RFail()

    monkeypatch.setattr(bench_own, "_lg_client", _client)
    monkeypatch.setattr(bench_own, "_sign_identity", lambda: None)
    # a non-empty identity that does NOT match the holder in `who` output
    # (an empty LG_USERNAME substring-matches anything — see _lg_client who check)
    monkeypatch.setenv("LG_USERNAME", "scope-test-identity")

    try:
        bench_own.acquire_bench_ownership(place="p-scope-fail", log=lambda *_: None)
    except bench_own.BenchOwnershipError:
        pass
    else:
        raise AssertionError("expected BenchOwnershipError on place failure")

    assert "BOLTY_SKIP_BENCH_LOCK" not in os.environ, (
        "cleanup path must restore the bypass"
    )
