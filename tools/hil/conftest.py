"""HIL test framework fixtures. All fixtures are lazy — importing this
conftest changes nothing for the overnight/difftest suites (their tests
request none of these).

Markers:
    hardware      — needs a reader + registered card (auto-skipped if absent)
    card_mutation — burns/wipes a card (excluded from `make test`; run via
                    `make test-hil` / explicit -m card_mutation)
    role_switch   — switches the stick role (restore-always via role_guard)
"""

import pytest

from hil import BoltyCli, BoltyError, CardRegistry
from hil.bolty import DEFAULT_CONSOLE_CTL

# ── Marker registration (no pyproject in this repo; conftest is the config) ──


def pytest_configure(config):
    for marker in (
        "hardware: requires a PC/SC reader with a registered card",
        "card_mutation: mutates card state (burn/wipe) — opt-in only",
        "role_switch: switches the M5Stick role (auto-restores)",
    ):
        config.addinivalue_line("markers", marker)


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def registry() -> CardRegistry:
    return CardRegistry()


@pytest.fixture(scope="session")
def cli() -> BoltyCli:
    BoltyCli.expect_binary()
    return BoltyCli()


@pytest.fixture(scope="session")
def console_ctl() -> str:
    return str(DEFAULT_CONSOLE_CTL)


@pytest.fixture(scope="session")
def acr_card_uid(registry: CardRegistry) -> str:
    """The ACR-side registered card UID (readable without a role switch —
    bolty-cli auto-picks the first reader with a card; preflight asserted
    the ACR card is the coupled one)."""
    uids = registry.uids_allowing("burn")
    uids = [u for u in uids if registry.lookup(u).reader_hint == "ACR1252"]
    if not uids:
        pytest.skip("no ACR-registered card in registry")
    return uids[0]
