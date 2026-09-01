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
    acr_uid = next(
        (u for u in registry.uids_allowing("burn")
         if registry.lookup(u).reader_hint == "ACR1252"),
        None,
    )
    if acr_uid:
        # bolty-cli picks the first reader WITH a card — the ACR card must
        # be the coupled one for the mutation tests to target it.
        check_card(pf, str(cli.binary), acr_uid, "read", registry,
                   reader_needle="ACR1252")
    else:
        pf.add("card:none-registered", "fail", False,
               "no burn-allowed ACR card in registry")

    print("\npreflight:\n" + pf.summary())
    assert not pf.hard_failures, (
        "preflight hard failures:\n" + pf.summary()
    )
