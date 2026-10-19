"""conftest hardening unit tests (ccid-firmware-rs port 2026-10-12).

Two rules ported from the sibling project, locked here as pure-logic
regression tests:

1. Path resolution helpers must never raise at pytest collection time —
   `candidate.exists()` + `read_bytes()` can raise EACCES (not just ENOENT)
   against root-owned target dirs on hosted runners (54524aa).
2. Labgrid place inheritance (fe17ea5): an "already acquired by this
   identity" outcome is success and must not be released at teardown —
   exercised on the bench tomorrow; here we lock the state-key wiring.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

HIL_DIR = Path(__file__).resolve().parent.parent


def _load_conftest():
    spec = importlib.util.spec_from_file_location("bolty_hil_conftest", HIL_DIR / "conftest.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_fw_sha256_never_raises_on_unreadable_paths(tmp_path, monkeypatch):
    conftest = _load_conftest()
    monkeypatch.setattr(conftest, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        Path, "home", staticmethod(lambda: tmp_path / "nohome"),
    )
    # Neither the release binary nor the backup exists / is readable.
    assert conftest._fw_sha256() == "unknown"


def test_fw_sha256_reads_the_binary_when_present(tmp_path, monkeypatch):
    conftest = _load_conftest()
    target_dir = tmp_path / "target" / "xtensa-esp32-espidf" / "release"
    target_dir.mkdir(parents=True)
    (target_dir / "bolty-esp32").write_bytes(b"dry-build")
    monkeypatch.setattr(conftest, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        Path, "home", staticmethod(lambda: tmp_path / "nohome"),
    )
    digest = conftest._fw_sha256()
    assert len(digest) == 16
    assert int(digest, 16) != 0


def test_place_state_keys_are_distinct():
    conftest = _load_conftest()
    # Two separate stash keys: acquired ≠ inherited. A collision here would
    # make teardown release a place an enclosing session still owns.
    assert conftest.LG_ACQUIRED_KEY != conftest.LG_INHERITED_KEY
    assert isinstance(conftest.LG_ACQUIRED_KEY, pytest.StashKey)
    assert isinstance(conftest.LG_INHERITED_KEY, pytest.StashKey)


def test_lg_acquire_inherits_already_acquired(monkeypatch):
    conftest = _load_conftest()

    class FakeSession:
        def __init__(self):
            self.stash = {}

    class InheritResult:
        returncode = 1
        stderr = "Error: You have already acquired this place"

    monkeypatch.setattr(conftest, "_lg_client", lambda *a, **k: InheritResult())
    session = FakeSession()
    assert conftest._lg_acquire_or_exit(session) is True
    assert session.stash.get(conftest.LG_INHERITED_KEY) is True


def test_lg_acquire_refuses_other_holder(monkeypatch):
    conftest = _load_conftest()

    class HeldResult:
        returncode = 1
        stderr = "Error: place is acquired by someone else"

    class FakePytestExit(Exception):
        pass

    def fake_exit(msg, returncode=None):
        raise FakePytestExit(msg)

    monkeypatch.setattr(conftest, "_lg_client", lambda *a, **k: HeldResult())
    monkeypatch.setattr(conftest.pytest, "exit", staticmethod(fake_exit))
    with pytest.raises(FakePytestExit):
        conftest._lg_acquire_or_exit(type("S", (), {"stash": {}})())


# ── B32 ACR check-in probe (2026-10-19) ────────────────────────────────


def test_acr_probe_isolated_parses_json(monkeypatch):
    from hil import acr_probe

    class OkRun:
        returncode = 0
        stdout = '{"state": "ok", "detail": "ATR 3b8180018080"}\n'
        stderr = ""

    monkeypatch.setattr(acr_probe.subprocess, "run", lambda *a, **k: OkRun())
    assert acr_probe.probe_isolated() == {
        "state": "ok", "detail": "ATR 3b8180018080",
    }


def test_acr_probe_isolated_timeout_is_the_wedge_signature(monkeypatch):
    import subprocess as sp

    from hil import acr_probe

    def hang(*a, **k):
        raise sp.TimeoutExpired(cmd="probe", timeout=25)

    monkeypatch.setattr(acr_probe.subprocess, "run", hang)
    result = acr_probe.probe_isolated()
    assert result["state"] == "wedge"
    assert "bulk pipe" in result["detail"]


def test_coupled_card_uid_skips_on_checkin_wedge():
    conftest = _load_conftest()
    reason = conftest._wedge_skip_reason("wedge")
    assert reason is not None and "B32" in reason
    assert conftest._wedge_skip_reason("ok") is None
    assert conftest._wedge_skip_reason("absent") is None
    assert conftest._wedge_skip_reason("no-service") is None
