"""h1_burn_regression hardening: #234 bench ownership + #235 stop-on-red.

Stub-driven (no hardware, no labgrid): BoltyCli/probe/lock seams are
monkeypatched; the assertions are about CONTROL FLOW — what runs, in
what order, and what must NEVER run after a red stage.
"""

import json
import sys
from pathlib import Path

import pytest

HIL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HIL_ROOT))

import h1_burn_regression as h1  # noqa: E402
from hil.bench_own import BenchOwnershipError  # noqa: E402

UID = "04337d8aae1790"

GOOD_BURN = "burned and verified successfully"
GOOD_INSPECT = "K0 auth: SUCCESS\nCMAC_valid=true\nCard state:     PROVISIONED"
GOOD_PICC = (
    "SDM verification PASSED\nUID matches:    YES\nCMAC valid:     YES\n"
    "p = " + "AB" * 16 + "\nc = " + "CD" * 8
)
GOOD_WIPE = "wiped and verified successfully"
GOOD_DIAGNOSE = "Card state:     BLANK"
START_DIAGNOSE = "Card state:     BLANK"


class StubCli:
    """Records every invocation; canned outputs per subcommand."""

    def __init__(self, outputs=None, fail_inspect=False):
        self.outputs = outputs or {}
        self.calls = []
        self.fail_inspect = fail_inspect

    def readers_line(self):
        self.calls.append(("readers_line",))
        return "ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 00 00"

    def uid(self):
        self.calls.append(("uid",))
        return UID

    def run(self, *args):
        self.calls.append(tuple(args))
        cmd = args[0]
        if cmd == "inspect" and self.fail_inspect:
            return "K0 auth: FAILED\nCMAC_valid=false"
        return self.outputs.get(cmd, {
            "burn": GOOD_BURN,
            "inspect": GOOD_INSPECT,
            "picc": GOOD_PICC,
            "wipe": GOOD_WIPE,
            "diagnose": GOOD_DIAGNOSE,
            "try-key": "Key accepted",
        }[cmd])

    def wiped(self):
        return any(c and c[0] == "wipe" for c in self.calls)


class StubRegistry:
    def __init__(self, *_a, **_k):
        pass

    def require(self, *_a):
        return None


class StubOwnership:
    def __init__(self):
        self.released = 0

    def release(self):
        self.released += 1


@pytest.fixture
def smoke_env(tmp_path, monkeypatch):
    monkeypatch.setenv("H1_SKIP_PROBE", "1")
    monkeypatch.setenv("HIL_UID", UID)
    monkeypatch.delenv("H1_SKIP_BENCH_LOCK", raising=False)
    monkeypatch.setattr(h1, "CardRegistry", StubRegistry)
    return tmp_path


# ── #235: stop-on-red inside one_cycle ─────────────────────────────────


def test_wipe_skipped_after_inspect_failure(tmp_path):
    cli = StubCli(fail_inspect=True)
    s = h1.one_cycle(cli, StubRegistry(), UID, "0" * 31 + "1",
                     "https://t.example", 1, tmp_path)
    assert s["failed_stage"] == "inspect_provisioned"
    assert s["all_pass"] is False
    # the evidence rule: wipe never ran, the provisioned state survives
    assert not cli.wiped()
    assert "wipe" not in s["results"] and "state_blank" not in s["results"]


def test_wipe_skipped_after_tap_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(h1, "http_code", lambda url, t: "503")
    cli = StubCli()
    s = h1.one_cycle(cli, StubRegistry(), UID, "0" * 31 + "1",
                     "https://t.example", 1, tmp_path)
    assert s["failed_stage"] == "worker_tap_200"
    assert not cli.wiped()


def test_wipe_skipped_after_burn_failure(tmp_path):
    cli = StubCli(outputs={"burn": "burn FAILED"})
    s = h1.one_cycle(cli, StubRegistry(), UID, "0" * 31 + "1",
                     "https://t.example", 1, tmp_path)
    assert s["failed_stage"] == "burn"
    assert not cli.wiped()
    # burn failed before anything mutated: nothing else ran either
    assert cli.calls == [("burn", "--issuer-key", "0" * 31 + "1",
                          "--url", h1.URL_TEMPLATE, "--confirm-uid", UID)]


def test_full_pass_runs_wipe_and_blank(tmp_path, monkeypatch):
    monkeypatch.setattr(h1, "http_code", lambda url, t: "200")
    cli = StubCli()
    s = h1.one_cycle(cli, StubRegistry(), UID, "0" * 31 + "1",
                     "https://t.example", 1, tmp_path)
    assert s["all_pass"] is True
    assert "failed_stage" not in s
    assert cli.wiped()
    assert (tmp_path / "summary.jsonl").exists()
    line = json.loads((tmp_path / "summary.jsonl").read_text().splitlines()[-1])
    assert line["all_pass"] is True


# ── #234: bench ownership in main() ────────────────────────────────────


def _run_main(monkeypatch, cli, ownership=None, acquire_exc=None):
    acquired = []

    def fake_acquire(log=print):
        acquired.append(True)
        if acquire_exc:
            raise acquire_exc
        return ownership or StubOwnership()

    monkeypatch.setattr(h1, "BoltyCli", lambda *a, **k: cli)
    monkeypatch.setattr(h1, "acquire_bench_ownership", fake_acquire)
    monkeypatch.setattr(h1, "bench_ownership_skipped", lambda: False)
    monkeypatch.setattr(h1, "http_code", lambda url, t: "200")
    rc = h1.main(["--cycles", "1", "--uid", UID, "--emu-card",
                  "--evidence", "/tmp/h1-test-ev", "--tap-base", "https://t.example"])
    return rc, acquired


def test_ownership_fail_closed_before_any_card_io(smoke_env, monkeypatch, tmp_path):
    cli = StubCli()
    rc, acquired = _run_main(monkeypatch, cli,
                             acquire_exc=BenchOwnershipError("place held"))
    assert rc == 2 and acquired == [True]
    # fail-closed: not even the reader line was touched
    assert ("readers_line",) not in cli.calls
    assert ("uid",) not in cli.calls


def test_ownership_released_after_success(smoke_env, monkeypatch):
    own = StubOwnership()
    cli = StubCli(outputs={"diagnose": START_DIAGNOSE})
    rc, _ = _run_main(monkeypatch, cli, ownership=own)
    assert rc == 0
    assert own.released == 1


def test_ownership_released_after_cycle_failure_path(smoke_env, monkeypatch):
    own = StubOwnership()
    cli = StubCli(outputs={"diagnose": START_DIAGNOSE}, fail_inspect=True)
    rc, _ = _run_main(monkeypatch, cli, ownership=own)
    # cycle 1 red at inspect -> main's stop rule -> rc 1, ownership released
    assert rc == 1
    assert own.released == 1


def test_ownership_taken_before_probe(smoke_env, monkeypatch):
    order = []

    def fake_probe():
        order.append("probe")
        return {"state": "ok", "detail": "stub"}

    def fake_acquire(log=print):
        order.append("acquire")
        return StubOwnership()

    monkeypatch.delenv("H1_SKIP_PROBE")
    monkeypatch.setattr(h1, "probe_isolated", fake_probe)
    monkeypatch.setattr(h1, "acquire_bench_ownership", fake_acquire)
    monkeypatch.setattr(h1, "bench_ownership_skipped", lambda: False)
    cli = StubCli(outputs={"diagnose": START_DIAGNOSE})
    monkeypatch.setattr(h1, "BoltyCli", lambda *a, **k: cli)
    monkeypatch.setattr(h1, "http_code", lambda url, t: "200")
    rc = h1.main(["--cycles", "1", "--uid", UID, "--emu-card",
                  "--evidence", "/tmp/h1-test-ev2", "--tap-base", "https://t.example"])
    assert rc == 0
    assert order[0] == "acquire" and "probe" in order


def test_smoke_mode_skips_ownership(smoke_env, monkeypatch):
    called = []
    monkeypatch.setattr(h1, "acquire_bench_ownership",
                        lambda log=print: called.append(1))
    monkeypatch.setenv("H1_SKIP_BENCH_LOCK", "1")
    # bench_ownership_skipped is env-driven, not stubbed here
    monkeypatch.setattr(h1, "bench_ownership_skipped", h1.bench_ownership_skipped)
    cli = StubCli(outputs={"diagnose": START_DIAGNOSE})
    monkeypatch.setattr(h1, "BoltyCli", lambda *a, **k: cli)
    monkeypatch.setattr(h1, "http_code", lambda url, t: "200")
    rc = h1.main(["--cycles", "1", "--uid", UID, "--emu-card",
                  "--evidence", "/tmp/h1-test-ev3", "--tap-base", "https://t.example"])
    assert rc == 0
    assert called == []
