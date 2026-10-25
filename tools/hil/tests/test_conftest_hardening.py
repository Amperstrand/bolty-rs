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


def test_pcscd_reader_wrapper_releases_reader_before_bench(monkeypatch):
    conftest = _load_conftest()
    if conftest.PcscdDomainHeldError is None:
        pytest.skip("tollgate-lab predates the pcscd domain lock")
    order = []

    class FakeBench:
        def release(self):
            order.append("bench")

    class FakeReader:
        holder = {"project": "x"}

        def release(self):
            order.append("reader")

    monkeypatch.setattr(conftest, "acquire_pcscd_reader", lambda **k: FakeReader())
    wrapped = conftest._wrap_pcscd_reader(FakeBench())
    wrapped.release()
    assert order == ["reader", "bench"]


def test_pcscd_reader_wrapper_loud_refusal_no_bench_leak(monkeypatch):
    conftest = _load_conftest()
    if conftest.PcscdDomainHeldError is None:
        pytest.skip("tollgate-lab predates the pcscd domain lock")

    class FakeBench:
        released = False

        def release(self):
            self.released = True

    def held(**k):
        raise conftest.PcscdDomainHeldError(
            holder={"role": "disturbance", "project": "flash-lane"}
        )

    class FakeExit(Exception):
        pass

    def fake_exit(msg, returncode=None):
        raise FakeExit(msg)

    monkeypatch.setattr(conftest, "acquire_pcscd_reader", held)
    monkeypatch.setattr(conftest.pytest, "exit", staticmethod(fake_exit))
    bench = FakeBench()
    with pytest.raises(FakeExit, match="flash-lane"):
        conftest._wrap_pcscd_reader(bench)
    assert bench.released


def test_pcscd_reader_wrapper_passthrough_when_unavailable(monkeypatch):
    conftest = _load_conftest()
    monkeypatch.setattr(conftest, "acquire_pcscd_reader", None)
    inner = object()
    assert conftest._wrap_pcscd_reader(inner) is inner


# ── #127 ACR-only place decoupling ─────────────────────────────────────


class _OptConfig:
    """Minimal config stub: getoption backed by a dict."""

    def __init__(self, opts):
        self._opts = opts

    def getoption(self, name, default=None):
        return self._opts.get(name, default)


def test_lg_place_resolution_order(monkeypatch):
    """#127: --lg-place beats BOLTY_LG_PLACE beats the full-rig default."""
    conftest = _load_conftest()
    monkeypatch.delenv("BOLTY_LG_PLACE", raising=False)
    assert conftest._lg_place(None) == "bolty-rig"
    assert conftest._lg_place(_OptConfig({})) == "bolty-rig"
    monkeypatch.setenv("BOLTY_LG_PLACE", "ref-acr1252")
    assert conftest._lg_place(None) == "ref-acr1252"
    assert conftest._lg_place(_OptConfig({})) == "ref-acr1252"
    assert (
        conftest._lg_place(_OptConfig({"lg_place": "bolty-rig"})) == "bolty-rig"
    ), "explicit --lg-place must beat the env default"


def test_lg_acquire_uses_and_stashes_configured_place(monkeypatch):
    """#127: the resolved place is what gets acquired AND what teardown
    will release — acquire/release must never split across places."""
    conftest = _load_conftest()

    calls = []

    class OkResult:
        returncode = 0
        stderr = ""

    def fake_client(place, *args, **kwargs):
        calls.append((place, args))
        return OkResult()

    monkeypatch.setattr(conftest, "_lg_client", fake_client)
    monkeypatch.delenv("BOLTY_LG_PLACE", raising=False)
    session = type(
        "S", (), {"stash": {}, "config": _OptConfig({"lg_place": "ref-acr1252"})}
    )()
    assert conftest._lg_acquire_or_exit(session) is False
    assert calls == [("ref-acr1252", ("acquire",))]
    assert session.stash.get(conftest.LG_PLACE_KEY) == "ref-acr1252"


def test_lg_release_uses_stashed_place(monkeypatch):
    conftest = _load_conftest()

    calls = []

    class OkResult:
        returncode = 0

    def fake_client(place, *args, **kwargs):
        calls.append((place, args))
        return OkResult()

    monkeypatch.setattr(conftest, "_lg_client", fake_client)
    session = type("S", (), {"stash": {conftest.LG_PLACE_KEY: "ref-acr1252"}})()
    conftest._lg_release_best_effort(session)
    assert calls == [("ref-acr1252", ("release",))]


def test_acr_only_place_constant_matches_makefile_leaf():
    """The leaf name must stay in lockstep with make test-hil's
    --lg-place=ref-acr1252 and labgrid-place.sh's ensure_place."""
    conftest = _load_conftest()
    assert conftest.LABGRID_PLACE_ACR_ONLY == "ref-acr1252"
    assert conftest.LABGRID_PLACE == "bolty-rig"


# ── B33 config audit (2026-10-25) ──────────────────────────────────────


def test_b33_parse_picc_param():
    from hil import acr_probe

    assert acr_probe.parse_picc_param([0x90, 0x3F]) == 0x3F
    assert acr_probe.parse_picc_param([0x90, 0xFF]) == 0xFF
    assert acr_probe.parse_picc_param([0x63, 0x00]) is None
    assert acr_probe.parse_picc_param([]) is None


def test_b33_parse_polling():
    from hil import acr_probe

    assert acr_probe.parse_polling([0xE1, 0x00, 0x00, 0x00, 0x01, 0x00]) == 0x00
    assert acr_probe.parse_polling([0xE1, 0x00, 0x00, 0x00, 0x01, 0x8B]) == 0x8B
    assert acr_probe.parse_polling([0xE1, 0x00, 0x00, 0x00, 0x02, 0x8B]) is None
    assert acr_probe.parse_polling(None) is None


def test_b33_audit_flags_the_incident_state():
    from hil import acr_probe

    ok, notes = acr_probe.audit_config(
        {"picc_param": 0x3F, "polling": 0x00}
    )
    assert not ok and "auto-poll OFF" in notes
    ok, _ = acr_probe.audit_config({"picc_param": 0xFF, "polling": 0x8B})
    assert ok
    ok, _ = acr_probe.audit_config({"picc_param": None, "polling": None})
    assert not ok


def test_b33_skip_reason_points_at_restore():
    conftest = _load_conftest()
    reason = conftest._wedge_skip_reason("cfg")
    assert reason is not None and "--restore" in reason and "B33" in reason
    assert conftest._wedge_skip_reason("ok") is None
