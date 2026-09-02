"""HIL test framework fixtures. All fixtures are lazy — importing this
conftest changes nothing for the overnight/difftest suites (their tests
request none of these).

Markers:
    hardware      — needs a reader + registered card (auto-skipped if absent)
    card_mutation — burns/wipes a card (excluded from `make test`; run via
                    `make test-hil` / explicit -m card_mutation)
    role_switch   — switches the stick role (restore-always via role_guard)
    env_dependent — drives real reader/card state — pass only on the coupled bench

Rig exclusivity: a session-scoped flock on results/.rig-lock prevents
parallel agents from interleaving role switches with card mutations.

Run ledger: every session appends to results/history.jsonl (OpenHTF pattern).
"""

import fcntl
import hashlib
import json
import time
from pathlib import Path

import pytest

from hil import BoltyCli, BoltyError, CardRegistry
from hil.bolty import DEFAULT_CONSOLE_CTL

RESULTS_DIR = Path(__file__).parent / "results"
LEDGER_PATH = RESULTS_DIR / "history.jsonl"
RIG_LOCK_PATH = RESULTS_DIR / ".rig-lock"
REPO_ROOT = Path(__file__).parent.parent.parent

# ── Marker registration ─────────────────────────────────────────────────


def pytest_configure(config):
    for marker in (
        "hardware: requires a PC/SC reader with a registered card",
        "card_mutation: mutates card state (burn/wipe) — opt-in only",
        "role_switch: switches the M5Stick role (auto-restores)",
        "env_dependent: drives real reader/card state — pass only on the "
        "coupled bench (mock seam not intercepted)",
    ):
        config.addinivalue_line("markers", marker)


# ── Rig exclusivity (flock) ────────────────────────────────────────────
# Prevents parallel agents from stomping the rig. Labgrid place acquisition
# supersedes this when the coordinator is running (see labgrid-places.yaml).


@pytest.fixture(scope="session")
def rig_lock():
    """Exclusive rig lock for the test session (flock, released on exit)."""
    RESULTS_DIR.mkdir(exist_ok=True)
    lock_fd = open(RIG_LOCK_PATH, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        pytest.exit(
            f"rig is locked by another session ({RIG_LOCK_PATH}) "
            "— wait or remove the lock file",
            returncode=3,
        )
    yield lock_fd
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    lock_fd.close()


# ── Run ledger (append-only history, OpenHTF/TofuPilot pattern) ───────


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Collect per-test outcomes for the ledger."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" or report.outcome == "skipped":
        if not hasattr(item.session, "hil_results"):
            item.session.hil_results = {}
        item.session.hil_results[item.nodeid] = {
            "outcome": report.outcome,
            "duration": round(getattr(report, "duration", 0), 3),
        }


def _fw_sha256() -> str:
    """sha256 of the workspace ESP32 release binary (what the stick runs per
    the AGENTS known-good stamping); falls back to the dated backup, then
    'unknown'. Short-prefix — trend correlation, not integrity proof."""
    for candidate in (
        REPO_ROOT / "target" / "xtensa-esp32-espidf" / "release" / "bolty-esp32",
        Path.home() / "fw-backup" / "bolty-esp32-knowngood-20260827-final.bin",
    ):
        if candidate.exists():
            return hashlib.sha256(candidate.read_bytes()).hexdigest()[:16]
    return "unknown"


def _coupled_uid() -> str:
    try:
        BoltyCli.expect_binary()
        return BoltyCli().uid_or_none() or "none"
    except Exception:
        return "none"


def _stamp_allure_environment(session) -> None:
    """Write environment.properties into the alluredir (#75) — fw_sha +
    card_uid correlation for trend reading. No-op without --alluredir."""
    try:
        alluredir = session.config.getoption("--alluredir")
    except (ValueError, KeyError):
        return
    if not alluredir:
        return
    lines = [
        f"fw_sha={_fw_sha256()}",
        f"card_uid={_coupled_uid()}",
        f"ts={time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
    ]
    Path(alluredir).mkdir(parents=True, exist_ok=True)
    (Path(alluredir) / "environment.properties").write_text("\n".join(lines) + "\n")


def pytest_sessionfinish(session, exitstatus):
    """Append a run record to history.jsonl after every session."""
    RESULTS_DIR.mkdir(exist_ok=True)
    results = getattr(session, "hil_results", {})
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exit": exitstatus,
        "total": len(results),
        "passed": sum(1 for r in results.values() if r["outcome"] == "passed"),
        "failed": sum(1 for r in results.values() if r["outcome"] == "failed"),
        "skipped": sum(1 for r in results.values() if r["outcome"] == "skipped"),
    }
    try:
        with open(LEDGER_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass  # best-effort
    _stamp_allure_environment(session)


# ── Fixtures ─────────────────────────────────────────────────────────────


def pytest_generate_tests(metafunc):
    """Parametrize card-consuming tests over every registry burn-allowed card
    (#77): each card gets a stable nodeid (…[04c474fa967380]); cards not
    physically coupled at run time auto-skip via the coupled_card_uid check.
    The registry stays the safety contract — parametrization only enumerates
    what it already permits."""
    if "coupled_card_uid" in metafunc.fixturenames:
        uids = CardRegistry().uids_allowing("burn")
        metafunc.parametrize("coupled_card_uid", uids, indirect=True)


@pytest.fixture(scope="session")
def registry() -> CardRegistry:
    return CardRegistry()


@pytest.fixture(scope="session")
def cli(rig_lock) -> BoltyCli:
    BoltyCli.expect_binary()
    return BoltyCli()


@pytest.fixture(scope="session")
def console_ctl() -> str:
    return str(DEFAULT_CONSOLE_CTL)


@pytest.fixture
def coupled_card_uid(request, cli, registry: CardRegistry) -> str:
    """The parametrized registered card UID, verified to be the one actually
    coupled (cli reads the ACR bench). Cards move between readers in the lab;
    the registry is the safety contract, not placement. Uses retry-aware
    uid(); params whose card is elsewhere auto-skip."""
    expected = request.param
    actual = cli.uid_or_none()
    if actual is None:
        pytest.skip("no card coupled (intermittent coupling — check antenna)")
    if actual != expected:
        card = registry.lookup(expected)
        pytest.skip(
            f"{card.alias if card else expected} ({expected}) not coupled — "
            f"on reader: {actual}"
        )
    registry.require(expected, "burn")
    return expected


@pytest.fixture
def ensure_blank(cli, registry: CardRegistry, coupled_card_uid: str):
    """Rerun-safety guard for mutation tests: if the card is non-blank at
    test start (after a failed prior attempt), wipe it to blank first so
    burn starts from a known state. Makes card_mutation tests safe with
    pytest-rerunfailures' flaky marker."""
    def _ensure():
        registry.require(coupled_card_uid, "wipe")
        try:
            diag = cli.run("diagnose", timeout_s=60)
            if "BLANK" in diag:
                return
        except BoltyError:
            return  # can't diagnose — burn will handle it
        issuer = "00000000000000000000000000000001"
        try:
            cli.run("wipe", "--issuer-key", issuer,
                    "--confirm-uid", coupled_card_uid, timeout_s=120)
        except BoltyError:
            pass  # burn will fail loudly if the card is truly stuck
    return _ensure
