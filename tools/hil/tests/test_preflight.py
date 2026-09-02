"""Preflight test: asserts the rig is in the state the mutation tests need.

Run:  make test-hil   (or pytest tools/hil/tests/test_preflight.py -m hardware)
This is the cheap gate — if it fails, burn/wipe/difftest would waste time.
"""

import pytest

from hil.preflight import (
    Preflight, check_card, check_console, check_readers,
)
from hil import CardRegistry, BoltyCli

pytestmark = pytest.mark.hardware


def test_preflight_acr_rig(cli, console_ctl, registry: CardRegistry):
    """ACR1252 + its registered card + console reachable (warn-only on
    console: the mutation tests don't need the stick)."""
    pf = Preflight()
    check_readers(pf, expect={"ACR1252": True, "GemPCTwin": False})
    check_console(pf, console_ctl)
    # Accept whichever registered burn-allowed card is actually coupled —
    # cards move between readers in the lab; the registry is the contract.
    try:
        actual = cli.uid()
    except Exception:  # noqa: BLE001
        actual = ""
    if actual and registry.lookup(actual) and "burn" in registry.lookup(actual).ops:
        card = registry.lookup(actual)
        pf.add(f"card:{actual}", "fail", True,
               f"coupled ({card.alias}, burn-allowed)")
    else:
        pf.add("card:coupled", "fail", False,
               f"coupled card '{actual or 'none'}' not burn-allowed in registry")

    print("\npreflight:\n" + pf.summary())
    assert not pf.hard_failures, (
        "preflight hard failures:\n" + pf.summary()
    )
