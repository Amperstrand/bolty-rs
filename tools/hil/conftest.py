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
        "env_dependent: drives real reader/card state — pass only on the "
        "coupled bench (mock seam not intercepted)",
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
def coupled_card_uid(cli, registry: CardRegistry) -> str:
    """The UID of whichever registered burn-allowed card is actually coupled
    (bolty-cli auto-picks the first reader with a card). Cards move between
    readers in the lab; the registry is the safety contract, not placement."""
    try:
        actual = cli.uid()
    except Exception as e:  # noqa: BLE001 — skip, not fail, when no card
        pytest.skip(f"no card coupled: {e}")
    card = registry.lookup(actual)
    if card is None or "burn" not in card.ops:
        pytest.skip(
            f"coupled card {actual} is not burn-allowed "
            f"(registry: {card.alias if card else 'unregistered'})"
        )
    return actual
