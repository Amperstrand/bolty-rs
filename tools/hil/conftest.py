"""HIL test framework fixtures. All fixtures are lazy — importing this
conftest changes nothing for the overnight/difftest suites (their tests
request none of these).

Markers:
    hardware      — needs a reader + registered card (auto-skipped if absent)
    card_mutation — burns/wipes a card (excluded from `make test`; run via
                    `make test-hil` / explicit -m card_mutation)
    role_switch   — switches the stick role (restore-always via role_guard)
    env_dependent — drives real reader/card state — pass only on the coupled bench

Rig exclusivity: three layers, taken in this order and never reversed
(AB-BA): (1) tollgate-lab BenchLock — a kernel flock on
/tmp/amperstrand-bench.lock, FIRST in every path, because it is the only
layer that excludes same-user sessions of OTHER harnesses on the shared
physical bench (cargo target/, lab-daemon ports, RF): labgrid places only
exclude per-place (upstream AcquirePlace rejects a second acquisition of
THE SAME place — microfips-bench vs bolty-rig never contend), and neither
cover non-labgrid resources nor survive coordinator restarts (upstream
load() drops acquired state). (2) the bolty-rig coordinator place, when
labgrid is up. (3) the local results/.rig-lock flock fallback.

Run ledger: every session appends to results/history.jsonl (OpenHTF pattern).
"""

import fcntl
import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest

from hil import BoltyCli, BoltyError, CardRegistry
from hil.bolty import DEFAULT_CONSOLE_CTL

# Guarded like the labgrid import (#82): GitHub host CI collects this
# conftest with only pytest/pytest-timeout/cryptography installed, and
# tollgate-lab depends on labgrid — a bare import would break the
# collection gate. On the bench host it is installed; rig_lock fails
# LOUDLY if a hardware run ever starts without it (silent degradation to
# place/flock-only is exactly the #199 collision class this closes).
try:
    from tollgate_lab import BenchLockHeldError, acquire_bench_lock
    _BENCH_LOCK_AVAILABLE = True
except ImportError:  # host CI collection — never drives hardware
    BenchLockHeldError = None
    acquire_bench_lock = None
    _BENCH_LOCK_AVAILABLE = False

RESULTS_DIR = Path(__file__).parent / "results"
LEDGER_PATH = RESULTS_DIR / "history.jsonl"
RIG_LOCK_PATH = RESULTS_DIR / ".rig-lock"
REPO_ROOT = Path(__file__).parent.parent.parent

# Coordinator binds only this address (see labgrid-env.yaml); mDNS does not
# resolve on this host.
LABGRID_COORDINATOR = "192.168.13.221:20408"
LABGRID_PLACE = "bolty-rig"
LG_ACQUIRED_KEY = pytest.StashKey[bool]()

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


# ── Rig exclusivity (#79) ──────────────────────────────────────────────
# Coordinator place acquisition when labgrid is up (visible to every client
# on the network, supersedes the local flock); flock fallback when it is not.
# With --lg-env the place is acquired in pytest_sessionstart — BEFORE the
# labgrid plugin's env/target fixtures expand resources (the plugin requires
# the place acquired, and fixture-store order does not guarantee rig_lock
# runs first).


def _lg_client(*args: str, timeout_s: float = 15):
    return subprocess.run(
        ["labgrid-client", "-x", LABGRID_COORDINATOR, "-p", LABGRID_PLACE, *args],
        capture_output=True, text=True, timeout=timeout_s,
    )


def _lg_coordinator_up() -> bool:
    try:
        return _lg_client("who", timeout_s=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _lg_acquire_or_exit():
    acquired = _lg_client("acquire")
    if acquired.returncode != 0:
        pytest.exit(
            f"rig place {LABGRID_PLACE} is acquired by another session "
            f"({acquired.stderr.strip() or 'see labgrid-client who'})",
            returncode=3,
        )


def pytest_sessionstart(session):
    lg_env = session.config.getoption("lg_env", None)
    if lg_env and _lg_coordinator_up():
        _lg_acquire_or_exit()
        session.stash[LG_ACQUIRED_KEY] = True


LG_ACQUIRED_KEY = pytest.StashKey[bool]()


@pytest.fixture(scope="session")
def rig_lock(request):
    """Exclusive rig ownership for the whole session. Three layers, in
    order (see the module docstring): the cross-harness bench flock FIRST,
    then the coordinator place when labgrid is up (loud refusal when
    another session holds it), then the local flock when it is down. With
    --lg-env the place is already held (pytest_sessionstart) — the flock
    still wraps it."""
    if not _BENCH_LOCK_AVAILABLE:
        pytest.exit(
            "tollgate-lab missing: cross-harness bench flock unavailable "
            "(pip install -e ~/src/tollgate-lab) — refusing to run hardware "
            "with degraded exclusivity (bolty-rs #85)",
            returncode=3,
        )
    try:
        bench_lock = acquire_bench_lock(
            "amperstrand-bench", project="bolty-hil", cwd=str(REPO_ROOT),
        )
    except BenchLockHeldError as exc:
        pytest.exit(f"bench flock held: {exc}", returncode=3)

    if request.session.stash.get(LG_ACQUIRED_KEY, False):
        yield "labgrid-place"
        bench_lock.release()
        return
    if _lg_coordinator_up():
        _lg_acquire_or_exit()
        yield "labgrid-place"
        _lg_client("release")
        bench_lock.release()
        return

    RESULTS_DIR.mkdir(exist_ok=True)
    lock_fd = open(RIG_LOCK_PATH, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        bench_lock.release()
        pytest.exit(
            f"rig is locked by another session ({RIG_LOCK_PATH}) "
            "— wait or remove the lock file",
            returncode=3,
        )
    yield lock_fd
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    lock_fd.close()
    bench_lock.release()


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
    if session.stash.get(LG_ACQUIRED_KEY, False):
        _lg_client("release")
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
