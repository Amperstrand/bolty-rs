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
load() drops acquired state). (2) the coordinator place when labgrid is
up — bolty-rig (full rig) by default, or the ref-acr1252 leaf for
ACR-only sessions via --lg-place/BOLTY_LG_PLACE (#127: the full-rig place
reserves the stick serial too). (3) the local results/.rig-lock flock
fallback.

Run ledger: every session appends to results/history.jsonl (OpenHTF pattern).
"""

import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hil import BoltyCli, BoltyError, CardRegistry
from hil.acr_probe import cfg_heal_hint, heal_hint, probe_isolated
from hil.bolty import DEFAULT_CONSOLE_CTL
from hil.labgrid_state import note_rig_state

# Guarded like the labgrid import (#82): GitHub host CI collects this
# conftest with only pytest/pytest-timeout/cryptography installed, and
# tollgate-lab depends on labgrid — a bare import would break the
# collection gate. On the bench host it is installed; rig_lock fails
# LOUDLY if a hardware run ever starts without it (silent degradation to
# place/flock-only is exactly the #199 collision class this closes).
try:
    from tollgate_lab import BenchLockHeldError, acquire_bench_lock
    from tollgate_lab.hardware import (
        PcscdDomainHeldError,
        acquire_pcscd_reader,
    )
    _BENCH_LOCK_AVAILABLE = True
except ImportError:  # host CI collection — never drives hardware
    BenchLockHeldError = None
    PcscdDomainHeldError = None
    acquire_bench_lock = None
    acquire_pcscd_reader = None
    _BENCH_LOCK_AVAILABLE = False

RESULTS_DIR = Path(__file__).parent / "results"
LEDGER_PATH = RESULTS_DIR / "history.jsonl"
RIG_LOCK_PATH = RESULTS_DIR / ".rig-lock"
REPO_ROOT = Path(__file__).parent.parent.parent

# Coordinator binds only this address (see labgrid-env.yaml); mDNS does not
# resolve on this host.
LABGRID_COORDINATOR = "192.168.13.208:20408"
# Full-rig place (stick serial + reference ACR) for suites that need both
# devices (difftest, burn_cycle). ACR-only sessions must acquire the
# LABGRID_PLACE_ACR_ONLY leaf instead (#127): acquiring the full-rig place
# reserves the stick serial too, so any m5stick holder blocks them even
# though the ACR is free.
LABGRID_PLACE = "bolty-rig"
LABGRID_PLACE_ACR_ONLY = "ref-acr1252"
LG_ACQUIRED_KEY = pytest.StashKey[bool]()
# Active place for this session (resolved from --lg-place / BOLTY_LG_PLACE);
# stashed at acquire time so teardown releases the place it took.
LG_PLACE_KEY = pytest.StashKey[str]()
# True when the place was already acquired by THIS identity (crashed prior
# session or wrapper script): acquisition is inherited, not taken — so
# teardown must NOT release it (ccid-firmware-rs fe17ea5 pattern; releasing
# an inherited place kills the enclosing session's exclusivity).
LG_INHERITED_KEY = pytest.StashKey[bool]()

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


def _lg_place(config) -> str:
    """Active rig place for this session (#127): the --lg-place option,
    then BOLTY_LG_PLACE, then the full-rig default. ACR-only suites pass
    ref-acr1252 (LABGRID_PLACE_ACR_ONLY) so a stick-serial holder cannot
    block them — one-device-one-exclusion-domain."""
    place = None
    if config is not None:
        # getattr guard: bare option access on a stub config (hardening
        # tests) must degrade to the env/default path, never raise.
        try:
            place = config.getoption("lg_place", None)
        except (ValueError, KeyError, AttributeError):
            place = None
    if place:
        return place
    return os.environ.get("BOLTY_LG_PLACE") or LABGRID_PLACE


def _lg_client(place: str, *args: str, timeout_s: float = 15):
    return subprocess.run(
        ["labgrid-client", "-x", LABGRID_COORDINATOR, "-p", place, *args],
        capture_output=True, text=True, timeout=timeout_s,
    )


def _lg_coordinator_up() -> bool:
    try:
        # `who` ignores -p upstream, so the probe place is irrelevant —
        # keep the full-rig constant to stay session-independent.
        return _lg_client(LABGRID_PLACE, "who", timeout_s=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _sign_hold_identity(config):
    """Bench canon (conwrt-bench docs/labgrid-coordination.md): every hold
    is signed so `labgrid-client who` answers who-and-why. Richer text by
    exporting LG_USERNAME yourself; this only fills the unset case."""
    import os

    if os.environ.get("LG_USERNAME"):
        return
    markexpr = config.getoption("-m", "") or "hil"
    try:
        import subprocess as sp

        sha = sp.run(["git", "rev-parse", "--short=7", "HEAD"],
                     capture_output=True, text=True, timeout=10,
                     cwd=REPO_ROOT).stdout.strip()
    except Exception:
        sha = "nogit"
    os.environ["LG_USERNAME"] = f"bolty-hil~mark={'-'.join(markexpr.split())}~sha={sha}"


def _wrap_pcscd_reader(bench_lock):
    """B32/tollgate-lab #15: reader sessions hold the pcscd domain in the
    SHARED role so disturbance sessions (stick flash, USB replug, pcscd
    restart via pcscd-ctl) cannot overlap them. Delegates .release() —
    reader role released BEFORE the bench flock (acquisition order
    reversed on teardown, AB-BA safe). No-op where tollgate-lab predates
    the domain lock; a held domain is a loud refusal, not a silent race."""
    if acquire_pcscd_reader is None:
        return bench_lock

    class _BenchLockWithReader:
        def __init__(self, inner, reader_lock):
            self._inner = inner
            self._reader = reader_lock

        def release(self) -> None:
            if self._reader is not None:
                try:
                    self._reader.release()
                finally:
                    self._reader = None
            self._inner.release()

    try:
        reader_lock = acquire_pcscd_reader(
            project="bolty-hil",
            reason="rig_lock: reader session (pcscd consumers)",
        )
    except PcscdDomainHeldError as exc:
        bench_lock.release()
        pytest.exit(f"pcscd domain held: {exc}", returncode=3)
    print("[pcscd-domain] reader role acquired (usb/pcscd disturbances excluded)")
    return _BenchLockWithReader(bench_lock, reader_lock)


def _acr_checkin(session) -> None:
    """B29 rule 1 / B32 / B33: probe the ACR1252 the moment the session
    owns the bench. 'wedge' prints the heal ladder; the deep class is
    owner-replug (no switched hub on this bench — owner decision
    2026-10-19), so burning session minutes on a wedged reader is the
    failure this prevents. BOLTY_ACR_AUTOHEAL=1 opts into the shallow heal
    (pcscd restart — shared infra, opt-in only). 'cfg' (B33 poll-off NVM
    drift) heals WITHOUT pcscd by default — direct-mode default restores
    under the already-held rig lock (BOLTY_ACR_CFG_HEAL=0 to skip)."""
    import os

    result = probe_isolated()
    session.stash[ACR_STATE_KEY] = result["state"]
    print(f"[acr-checkin] {result['state']}: {result['detail']}")
    if result["state"] == "wedge":
        print(heal_hint())
        if os.environ.get("BOLTY_ACR_AUTOHEAL") == "1":
            healed = subprocess.run(
                ["systemctl", "restart", "pcscd"],
                capture_output=True, text=True, timeout=30,
            )
            time.sleep(3)
            result = probe_isolated()
            session.stash[ACR_STATE_KEY] = result["state"]
            print(
                f"[acr-checkin] after autoheal (rc={healed.returncode}): "
                f"{result['state']}: {result['detail']}"
            )
    elif result["state"] == "cfg":
        if os.environ.get("BOLTY_ACR_CFG_HEAL") != "0":
            print(cfg_heal_hint())
            healed = subprocess.run(
                [sys.executable, "-m", "hil.acr_probe", "--restore", "--json"],
                capture_output=True, text=True, timeout=30,
                cwd=str(REPO_ROOT / "tools" / "hil"),
            )
            result = probe_isolated()
            session.stash[ACR_STATE_KEY] = result["state"]
            print(
                f"[acr-checkin] after B33 cfg-heal (rc={healed.returncode}): "
                f"{result['state']}: {result['detail']}"
            )
        else:
            print("[acr-checkin] BOLTY_ACR_CFG_HEAL=0 — leaving reader "
                  "config as found (B33 drift NOT healed)")
    elif result["state"] == "absent":
        print("[acr-checkin] ACR1252 not listed by pcscd — hardware tests "
              "will skip via coupled_card_uid")


def _lg_client_p(place: str, *args: str, timeout_s: float = 15):
    """labgrid-client against an explicit place (reservation tokens use
    '+<token>' as the -p argument)."""
    return subprocess.run(
        ["labgrid-client", "-x", LABGRID_COORDINATOR, "-p", place, *args],
        capture_output=True, text=True, timeout=timeout_s,
    )


LG_RESERVE_TOKEN_KEY = pytest.StashKey[str]()
# B32/B33 ACR check-in state ('ok' | 'wedge' | 'cfg' | 'absent' |
# 'no-service' | 'unknown'); set when the rig is held, read by
# coupled_card_uid and the session ledger. None key default = probe not
# run (non-hardware session).
ACR_STATE_KEY = pytest.StashKey[str]()
RIG_HELD_KEY = pytest.StashKey[bool]()


def _reserve_wait(session, place: str, prio: int, timeout_s: int) -> str:
    """Queue for the rig place via a coordinator reservation instead of
    exiting when busy (the canon's polite-queue pattern: once allocated,
    only this reservation's owner can lock the place)."""
    import re

    try:
        r = subprocess.run(
            ["labgrid-client", "-x", LABGRID_COORDINATOR, "reserve", "--wait",
             "--prio", str(prio), f"name={place}"],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        pytest.exit(f"reservation for {place} timed out after {timeout_s}s", returncode=3)
    if r.returncode != 0:
        pytest.exit(f"reservation for {place} failed: {(r.stderr or r.stdout).strip()[:200]}",
                    returncode=3)
    m = re.search(r"^\s*token:\s*(\S+)", r.stdout, re.M)
    if not m:
        pytest.exit(f"no reservation token in output: {r.stdout!r}", returncode=3)
    return m.group(1)


def _lg_acquire_or_exit(session) -> bool:
    """Acquire the rig place. Returns True when the place was INHERITED
    (already acquired by this same identity) — callers must not release an
    inherited place. Any other holder is a loud refusal."""
    # getattr: the hardening tests drive this path with a bare stash-only
    # session mock (test_conftest_hardening contract).
    config = getattr(session, "config", None)
    place = _lg_place(config)
    session.stash[LG_PLACE_KEY] = place
    try:
        acquired = _lg_client(place, "acquire")
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.exit(f"labgrid-client failed during acquire: {exc}", returncode=3)
    if acquired.returncode != 0:
        stderr = acquired.stderr.strip()
        if "already acquired" in stderr:
            session.stash[LG_INHERITED_KEY] = True
            return True
        reserve = config.getoption("reserve", False) if config is not None else False
        if reserve:
            prio = config.getoption("reserve_priority", 0)
            timeout_s = config.getoption("reserve_timeout_min", 120) * 60
            token = _reserve_wait(session, place, prio, timeout_s)
            session.stash[LG_RESERVE_TOKEN_KEY] = token
            alloc = _lg_client_p(f"+{token}", "acquire", timeout_s=timeout_s)
            if alloc.returncode != 0:
                subprocess.run(["labgrid-client", "-x", LABGRID_COORDINATOR,
                                "cancel-reservation", token],
                               capture_output=True, timeout=30)
                pytest.exit(f"could not acquire allocated {place}: "
                            f"{alloc.stderr.strip()[:200]}", returncode=3)
            print(f"[labgrid] {place} acquired via reservation {token}")
            return False
        pytest.exit(
            f"rig place {place} is acquired by another session "
            f"({stderr or 'see labgrid-client who'}); pass --reserve to queue "
            f"politely instead of failing",
            returncode=3,
        )
    return False


def pytest_addoption(parser):
    group = parser.getgroup("bolty-hil")
    group.addoption("--reserve", action="store_true", default=False,
                    help="Queue for the rig place via a coordinator "
                         "reservation instead of failing when busy.")
    group.addoption("--reserve-priority", type=int, default=0,
                    help="Reservation priority (CI lanes use negative).")
    group.addoption("--reserve-timeout-min", type=int, default=120,
                    help="How long --reserve may block waiting (minutes).")
    group.addoption("--lg-place", action="store", default=None, metavar="PLACE",
                    help="Labgrid place to acquire (default bolty-rig; ACR-only "
                         "suites pass ref-acr1252 per #127 — the full-rig place "
                         "also reserves the stick serial). BOLTY_LG_PLACE sets "
                         "the same default.")


def pytest_sessionstart(session):
    lg_env = session.config.getoption("lg_env", None)
    if lg_env and _lg_coordinator_up():
        _sign_hold_identity(session.config)
        _lg_acquire_or_exit(session)
        session.stash[LG_ACQUIRED_KEY] = True


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
    # #209: this session holds the bench flock — bolty-cli children spawned
    # by tests must skip their own flock (flock is per-open-fd; a child
    # would otherwise refuse against this, the holding, parent).
    os.environ.setdefault("BOLTY_SKIP_BENCH_LOCK", "1")
    bench_lock = _wrap_pcscd_reader(bench_lock)

    # Pattern 15 (docs/labgrid-bench-sharing.md P1): mirror rig state onto
    # the place tags once the session owns the bench — best-effort. Suite
    # label from -m (test-hil vs difftest differ only in the marker expr).
    markexpr = request.config.getoption("-m", "") or "hil"
    note_rig_state(test=f"pytest:{'-'.join(markexpr.split())}",
                   firmware=_fw_sha256())

    request.session.stash[RIG_HELD_KEY] = True
    _acr_checkin(request.session)

    # Shared disk hygiene (2026-09-11 ENOSPC incident): no-op with
    # headroom, conservative prunes without — tollgate_lab owns it. Only
    # reachable on bench sessions (the flock is bench-only).
    try:
        from tollgate_lab import ensure_run_headroom

        hygiene = ensure_run_headroom()
        if hygiene.acted:
            print(f"disk hygiene: {hygiene.actions}")
    except Exception:
        pass  # hygiene must never gate a hardware run

    if request.session.stash.get(LG_ACQUIRED_KEY, False):
        yield "labgrid-place"
        bench_lock.release()
        return
    if _lg_coordinator_up():
        _sign_hold_identity(request.config)
        inherited = _lg_acquire_or_exit(request.session)
        if not inherited:
            request.session.stash[LG_ACQUIRED_KEY] = True
        yield "labgrid-place"
        if not inherited:
            _lg_release_best_effort(request.session)
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
    'unknown'. Short-prefix — trend correlation, not integrity proof.
    Path stats/reads are OSError-guarded: hosted CI collects this conftest
    against root-owned target dirs where stat() raises EACCES, not ENOENT
    (ccid-firmware-rs 54524aa rule: resolution helpers never raise)."""
    for candidate in (
        REPO_ROOT / "target" / "xtensa-esp32-espidf" / "release" / "bolty-esp32",
        Path.home() / "fw-backup" / "bolty-esp32-knowngood-20260827-final.bin",
    ):
        try:
            return hashlib.sha256(candidate.read_bytes()).hexdigest()[:16]
        except OSError:
            continue
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


def _lg_release_best_effort(session):
    """Release the place this session acquired (stashed at acquire time so
    a mid-session option/env change can never split acquire/release)."""
    place = session.stash.get(LG_PLACE_KEY, None) or _lg_place(
        getattr(session, "config", None)
    )
    try:
        _lg_client(place, "release")
    except (OSError, subprocess.TimeoutExpired):
        pass  # teardown must never crash; coordinator restarts wipe places anyway


def pytest_sessionfinish(session, exitstatus):
    """Append a run record to history.jsonl after every session."""
    if session.stash.get(RIG_HELD_KEY, False):
        checkout = probe_isolated()
        print(f"[acr-checkout] {checkout['state']}: {checkout['detail']}")
        if checkout["state"] == "wedge":
            print(heal_hint())
        elif checkout["state"] == "cfg":
            print(cfg_heal_hint() + " — config left drifted at checkout "
                  "(B33: the next session's check-in will heal it)")
    if session.stash.get(LG_ACQUIRED_KEY, False) and not session.stash.get(
        LG_INHERITED_KEY, False
    ):
        _lg_release_best_effort(session)
    token = session.stash.get(LG_RESERVE_TOKEN_KEY, None)
    if token:
        subprocess.run(["labgrid-client", "-x", LABGRID_COORDINATOR,
                        "cancel-reservation", token],
                       capture_output=True, timeout=30)
    RESULTS_DIR.mkdir(exist_ok=True)
    results = getattr(session, "hil_results", {})
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exit": exitstatus,
        "total": len(results),
        "passed": sum(1 for r in results.values() if r["outcome"] == "passed"),
        "failed": sum(1 for r in results.values() if r["outcome"] == "failed"),
        "skipped": sum(1 for r in results.values() if r["outcome"] == "skipped"),
        "acr_state": session.stash.get(ACR_STATE_KEY, None),
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


def _wedge_skip_reason(acr_state: str):
    """B32/B33: a wedge or unhealed config drift detected at check-in must
    fail fast with the pointer, not burn session minutes on per-test
    timeouts."""
    if acr_state == "wedge":
        return ("ACR1252 wedge detected at check-in (B32) — heal per the "
                "session-header ladder before spending session time")
    if acr_state == "cfg":
        return ("ACR1252 auto-polling disabled in NVM at check-in (B33) — "
                "run `python3 -m hil.acr_probe --restore` from tools/hil/")
    return None


@pytest.fixture
def coupled_card_uid(request, cli, registry: CardRegistry) -> str:
    """The parametrized registered card UID, verified to be the one actually
    coupled (cli reads the ACR bench). Cards move between readers in the lab;
    the registry is the safety contract, not placement. Uses retry-aware
    uid(); params whose card is elsewhere auto-skip."""
    expected = request.param
    reason = _wedge_skip_reason(
        request.session.stash.get(ACR_STATE_KEY, "ok")
    )
    if reason:
        pytest.skip(reason)
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
            diag = cli.run(
                "diagnose", "--issuer-key", "00000000000000000000000000000001",
                timeout_s=60,
            )
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
