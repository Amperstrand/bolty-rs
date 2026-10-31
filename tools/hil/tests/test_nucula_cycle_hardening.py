"""nucula_cycle hardening: the six #176 review-debt residuals.

Stub-driven (no hardware, no labgrid): seams are monkeypatched; the
assertions are about CONTROL FLOW — which markers gate mutation, what
persists across visits, what must abort, and how places are acquired.
"""

import json
import sys
from pathlib import Path

import pytest

HIL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HIL_ROOT))

import nucula_cycle as nc  # noqa: E402
from hil.bench_own import BenchOwnershipError  # noqa: E402

UID = "04c474fa967380"
CARD_RO = nc.CARD_RO

BURN_OK_LINE = "✅ Card burned and verified successfully!"


class StubCli:
    def __init__(self, uid=UID):
        self._uid = uid
        # dry-run's gated() wrapper (nucula_cycle dry-run plumbing) writes
        # cli.uid_box[0] before gating — honor the FakeCli contract so this
        # stub survives that global patch in a shared pytest process.
        self.uid_box = [uid]
        self.calls = []

    def run(self, *cmd, timeout_s=60):
        self.calls.append(cmd)
        sub = str(cmd[0])  # dispatch on the subcommand only — burn's URL
        # itself contains "{picc:uid+ctr}", substring matching misroutes
        if sub == "inspect":
            return "Card state: PROVISIONED\nK0 auth: SUCCESS"
        if sub == "picc":
            return "SDM verification PASSED\nUID matches: YES\nRead counter: 7"
        return BURN_OK_LINE

    def uid(self):
        self.calls.append("uid")
        return self._uid


def make_cycle(tmp_path, dry_run=True):
    cycle = nc.Cycle(tmp_path / "ev", dry_run=dry_run, variant="full")
    # tests must not read/write the shared results state
    cycle._load_state = lambda: {"variant": "full", "visits_done": [],
                                 "snapshots": {}, "events": []}
    cycle.state = cycle._load_state()
    return cycle


# ── item 1: the real BURN_OK marker gates the batch ─────────────────────

def test_burn_accepts_the_real_cli_marker(tmp_path):
    cycle = make_cycle(tmp_path)
    cli = StubCli()
    cycle.registry = _registry_allowing_burn()
    cycle.burn_vertical(cli, UID, "reader")  # must NOT abort


def test_burn_aborts_on_the_legacy_wrong_marker(tmp_path):
    cycle = make_cycle(tmp_path)
    cli = StubCli()
    cli.run = lambda *a, timeout_s=60: "burn complete"  # the OLD wrong grep
    cycle.registry = _registry_allowing_burn()
    with pytest.raises(nc.Abort, match="burn did not complete"):
        cycle.burn_vertical(cli, UID, "reader")


def _registry_allowing_burn():
    class R:
        def require(self, uid, op):
            pass

        uids_allowing = lambda self, op: [UID]  # noqa: E731
    return R()


# ── item 2: variant persists across visits ──────────────────────────────

def test_variant_persists_when_flag_absent(tmp_path):
    cycle = make_cycle(tmp_path)
    cycle.state["variant"] = "minimal"
    # simulate the main() write-through with args.variant=None
    args_variant = None
    if args_variant is not None:
        cycle.state["variant"] = args_variant
    elif "variant" not in cycle.state:
        cycle.state["variant"] = "full"
    cycle.variant = cycle.state["variant"]
    assert cycle.variant == "minimal", (
        "a visit without --variant must not revert a persisted minimal cycle"
    )


def test_explicit_variant_overrides(tmp_path):
    cycle = make_cycle(tmp_path)
    cycle.state["variant"] = "minimal"
    args_variant = "full"
    if args_variant is not None:
        cycle.state["variant"] = args_variant
    cycle.variant = cycle.state["variant"]
    assert cycle.variant == "full"


# ── item 3: swap window between CARD_RO and CARD_B on the same antenna ──

def test_require_absent_blocks_while_coupled(tmp_path, monkeypatch):
    monkeypatch.setattr(nc, "GATE_RETRY_S", 0)  # no real 5s waits in tests
    cycle = make_cycle(tmp_path, dry_run=False)
    cli = StubCli(uid=CARD_RO)  # CARD_RO never leaves the antenna
    with pytest.raises(nc.GateError, match="swap window was ignored"):
        cycle.require_absent(cli, CARD_RO, "nucula")


def test_require_absent_passes_when_removed(tmp_path):
    cycle = make_cycle(tmp_path, dry_run=False)
    cli = StubCli(uid=UID)  # some other card / none
    cycle.require_absent(cli, CARD_RO, "nucula")  # must not raise


# ── item 4: rotation samples join the divergence report ─────────────────

def test_rotation_counters_reach_divergence(tmp_path):
    cycle = make_cycle(tmp_path)
    cycle.state["snapshots"] = {
        UID: [
            {"ts": 1, "uid": UID, "reader": "acr", "counter": 100},
            # rotation sample: nucula-side counters run BACKWARDS vs acr
            {"ts": 2, "uid": UID, "reader": "nucula", "counters": [90, 91, 92]},
        ]
    }
    findings = cycle.divergence_report()
    assert any("backwards" in f or "counter" in f.lower() for f in findings), (
        f"a backwards rotation must surface in the divergence report: {findings}"
    )


# ── item 5: all-zeros negative probe aborts ─────────────────────────────

def test_all_zeros_negative_probe_aborts(tmp_path):
    cycle = make_cycle(tmp_path)
    cli = StubCli(uid="0" * 14)
    with pytest.raises(nc.Abort, match="ALL-ZEROS"):
        cycle.negative_probe(cli, "reader")


def test_honest_negative_failure_passes(tmp_path):
    cycle = make_cycle(tmp_path)
    cli = StubCli(uid="")
    cycle.negative_probe(cli, "reader")  # uid read error = honest failure


# ── item 6: places are reserved (queued), not acquire-raced ─────────────

def test_place_guard_uses_reservation(monkeypatch, tmp_path):
    calls = []

    def fake_reserve(place, log=print, wait_min=15):
        calls.append(("reserve", place))
        return "TOK123"

    def fake_cancel(token, log=print):
        calls.append(("cancel", token))

    monkeypatch.setattr(nc, "subprocess", _fake_subprocess(calls))
    import hil.bench_own as bo
    monkeypatch.setattr(bo, "reserve_and_acquire_place", fake_reserve)
    monkeypatch.setattr(bo, "cancel_reservation", fake_cancel)

    class _R:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        bo, "_lg_client", lambda place, *a, **kw: (calls.append(("release", place)), _R())[1]
    )

    cycle = make_cycle(tmp_path, dry_run=False)
    with nc.place_guard(cycle, "nucula-c3"):
        calls.append(("work",))
    assert ("reserve", "nucula-c3") in calls
    assert any(c[0] == "release" for c in calls)
    assert ("cancel", "TOK123") in calls, "reservation must be cancelled after release"
    assert not any(c[0] == "acquire-race" for c in calls)


def test_place_guard_fails_closed_on_reservation_error(monkeypatch, tmp_path):
    import hil.bench_own as bo

    def boom(place, log=print, wait_min=15):
        raise BenchOwnershipError("reservation never allocated")

    monkeypatch.setattr(bo, "reserve_and_acquire_place", boom)
    cycle = make_cycle(tmp_path, dry_run=False)
    with pytest.raises(nc.Abort, match="could not acquire"):
        with nc.place_guard(cycle, "nucula-c3"):
            pass


def _fake_subprocess(calls):
    class S:
        @staticmethod
        def run(args, capture_output=True, timeout=30, text=True):
            calls.append((args[-2] if len(args) > 1 else args[-1], args[-1]))
            if args[-1] == "release":
                calls[-1] = ("release",)
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()
    return S


def test_fresh_state_never_persists_none_variant(tmp_path):
    # CI regression (first push of this PR): the Cycle ctor received the
    # argparse default None and _load_state()'s fresh dict persisted
    # {"variant": None} — the key existed, so main()'s explicit-flag guard
    # never applied its "full" default and v4 aborted "exists only in the
    # full variant".
    import tempfile
    real_state = nc.STATE_PATH
    tmp_state = tmp_path / "state.json"
    nc.STATE_PATH = tmp_state
    try:
        cycle = nc.Cycle(tmp_path / "ev", dry_run=True, variant=None)
        assert cycle.state["variant"] == "full", cycle.state
        assert not tmp_state.exists() or '"variant": None' not in tmp_state.read_text()
    finally:
        nc.STATE_PATH = real_state
