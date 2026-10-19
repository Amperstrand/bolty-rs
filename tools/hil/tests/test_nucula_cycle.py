"""Host-only tests for the nucula cycle runner (no hardware, no labgrid).

Covers the safety-critical properties:
- UID gate aborts before ANY mutation when the wrong card is coupled
- unregistered cards are refused by the registry gate
- visit sequencing refuses to skip ahead
- the dry-run walk completes full and minimal variants
- minimal variant never burns CARD_B
- the divergence report catches backwards counters
- BoltyCli injects BOLTY_READER for the nucula pin (#121)
"""

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

HIL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HIL_DIR))

nc = importlib.import_module("nucula_cycle")

from hil import CardRegistry  # noqa: E402


class SpyCli(nc.BoltyCli):
    """Records every command; returns a configurable UID."""

    def __init__(self, uid_value, reader=None):
        super().__init__(reader=reader)
        self.uid_value = uid_value
        self.calls = []

    def run(self, *args, timeout_s=None):
        self.calls.append(args[0])
        if args[0] == "uid":
            return f"UID: {self.uid_value}"
        if args[0] == "burn":
            return "burn complete"
        if args[0] == "inspect":
            return "Card state: PROVISIONED"
        if args[0] == "picc":
            return "UID matches: YES\nRead counter: 42\np=" + "A" * 32 + "\nc=" + "B" * 16
        if args[0] == "wipe":
            return "wipe complete"
        if args[0] == "diagnose":
            return "Card state: BLANK"
        if args[0] == "url":
            return "https://boltcardpoc.psbt.me/?p=X&c=Y"
        raise AssertionError(f"unexpected {args}")

    def uid(self, retries=1):
        self.calls.append("uid")
        return self.uid_value


@pytest.fixture()
def cycle(tmp_path, monkeypatch):
    monkeypatch.setattr(nc, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(nc, "AUDIT_PATH", tmp_path / "audit.log")
    return nc.Cycle(tmp_path / "evidence", dry_run=True)


def test_gate_aborts_on_wrong_uid_before_mutation(cycle):
    spy = SpyCli("deadbeefdeadbe")
    with pytest.raises(nc.GateError, match="deadbeefdeadbe"):
        cycle.gate(spy, nc.CARD_A, "burn", "acr")
    assert "burn" not in spy.calls and "wipe" not in spy.calls


def test_gate_converts_no_card_error(cycle):
    class NoCardCli(SpyCli):
        def uid(self, retries=1):
            raise nc.BoltyError("no card present", 3, "")

    with pytest.raises(nc.GateError, match="no card coupled"):
        cycle.gate(NoCardCli("x"), nc.CARD_A, "burn", "acr")


def test_gate_refuses_unregistered_card(cycle):
    registry = CardRegistry()
    with pytest.raises(Exception):
        registry.require("113522ba", "read")
    spy = SpyCli("113522ba")
    with pytest.raises(Exception):
        cycle.gate(spy, "113522ba", "read", "acr")


def test_gate_refuses_read_only_card_for_burn(cycle, tmp_path):
    # Hermetic registry: the REAL cards.toml no longer carries a read-only
    # card (043365fa967380 was recovered 2026-10-19, c12a8d2 — ops widened
    # to read/burn/wipe), so the test declares its own read-only entry
    # instead of depending on live registry policy.
    ro_registry = tmp_path / "cards-ro.toml"
    ro_registry.write_text(
        f"[cards.{nc.CARD_RO}]\nops = [\"read\"]\n"
    )
    cycle.registry = CardRegistry(ro_registry)
    spy = SpyCli(nc.CARD_RO)
    with pytest.raises(Exception):
        cycle.gate(spy, nc.CARD_RO, "burn", "acr")
    assert "burn" not in spy.calls


def test_visit_sequencing_refuses_skips(cycle):
    with pytest.raises(nc.Abort, match="v1"):
        nc.visit_v2(cycle, argparse_stub())


def argparse_stub(**kw):
    import argparse
    ap = argparse.Namespace(with_negative=False, with_ro=False)
    for k, v in kw.items():
        setattr(ap, k, v)
    return ap


def test_dry_run_full_walk(tmp_path, monkeypatch):
    monkeypatch.setattr(nc, "STATE_PATH", tmp_path / "s.json")
    monkeypatch.setattr(nc, "AUDIT_PATH", tmp_path / "a.log")
    monkeypatch.setattr(nc, "EVIDENCE_DEFAULT", tmp_path / "ev")
    monkeypatch.setattr(sys, "argv", ["nucula_cycle.py", "--visit", "v1",
                                      "--dry-run", "--evidence-dir", str(tmp_path / "ev")])
    rc = nc.main()
    assert rc == 0
    for visit in ("v2", "v3", "v4"):
        monkeypatch.setattr(sys, "argv", ["nucula_cycle.py", "--visit", visit,
                                          "--dry-run", "--evidence-dir", str(tmp_path / "ev")])
        assert nc.main() == 0, f"{visit} failed"
    state = json.loads((tmp_path / "s.json").read_text())
    assert state["visits_done"] == ["v1", "v2", "v3", "v4"]
    assert nc.next_move_hint(nc.Cycle(tmp_path / "ev")) == "cycle complete"


def test_dry_run_minimal_never_burns_card_b(tmp_path, monkeypatch):
    burns = []
    real_run = nc.BoltyCli.run

    def spy_run(self, *args, timeout_s=None):
        if args and args[0] == "burn":
            burns.append(args)
        return real_run(self, *args, timeout_s=timeout_s)

    monkeypatch.setattr(nc.BoltyCli, "run", spy_run)
    monkeypatch.setattr(nc, "STATE_PATH", tmp_path / "s.json")
    monkeypatch.setattr(nc, "AUDIT_PATH", tmp_path / "a.log")
    monkeypatch.setattr(sys, "argv", ["nucula_cycle.py", "--visit", "v1", "--variant",
                                      "minimal", "--dry-run", "--evidence-dir", str(tmp_path / "ev")])
    assert nc.main() == 0
    for visit in ("v2", "v3"):
        monkeypatch.setattr(sys, "argv", ["nucula_cycle.py", "--visit", visit, "--variant",
                                          "minimal", "--dry-run", "--evidence-dir", str(tmp_path / "ev")])
        assert nc.main() == 0
    card_b_burns = [b for b in burns if nc.CARD_B in " ".join(b)]
    assert not card_b_burns, f"minimal variant burned CARD_B: {card_b_burns}"


def test_divergence_report_flags_backwards_counter(cycle):
    cycle.snapshot(nc.CARD_A, "acr", kind="picc", counter=100)
    cycle.snapshot(nc.CARD_A, "nucula", kind="picc", counter=99)
    findings = cycle.divergence_report()
    assert any("BACKWARDS" in f for f in findings)


def test_boltycli_reader_env_injection(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output=True, text=True, timeout=None, env=None):
        captured["env"] = env
        captured["cmd"] = cmd

        class R:
            returncode = 0
            stdout = "UID: 04c474fa967380"
            stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    nc.BoltyCli(reader="Nucula").run("uid")
    assert captured["env"]["BOLTY_READER"] == "Nucula"
    nc.BoltyCli().run("uid")
    assert captured["env"] is None
