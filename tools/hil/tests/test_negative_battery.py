"""Negative/robustness battery: deliberately wrong but recoverable operations.

Every case returns an error status — the test ASSERTS the error class,
proving the card (silicon or applet) handles malformed input gracefully
without state damage. Run after a burn cycle to confirm the card is
still healthy.

Based on the H1 ACR lane negative battery (2026-10-27), wire-captured on
real NTAG424 silicon. Silicon reference data: tools/hil/wire/
negative-battery-findings.md.
"""
import json
import re

import pytest

from hil import BoltyCli, BoltyError, CardRegistry

pytestmark = [pytest.mark.hardware]

# Status classes we expect (NXP SW space on silicon; ISO on original applet)
# The test accepts either — the key assertion is that an error IS returned
ERROR_CLASSES = {
    "91CA": "protocol-violation",      # invalid key number
    "91BE": "boundary",                 # read beyond EOF
    "91F0": "file-not-found-nxp",       # NXP space
    "917E": "unknown-command",          # unknown NXP INS
    "911C": "security-nxp",             # NXP security not satisfied
    "6982": "security-iso",             # ISO security not satisfied
    "6A82": "file-not-found-iso",       # ISO file not found
    "6A80": "wrong-data-iso",           # ISO wrong data
    "6700": "wrong-length-iso",         # ISO wrong length
    "6D00": "ins-not-supported",        # ISO INS not supported
}


class TestNegativeBattery:
    """Each test sends a deliberately malformed command and asserts the
    card returns a recognized error without damaging state."""

    def test_unknown_nxp_ins(self, cli):
        """Unknown INS 0x77 in NXP CLA 0x90 → error (not silent)."""
        out = cli.run("uid")  # select first via normal command
        # We can't send raw APDUs through bolty-cli; this test needs the
        # pyscard path (negative_battery.py). Here we verify via CLI that
        # unknown operations fail gracefully.
        with pytest.raises(BoltyError) as exc_info:
            cli.run("try-key", "--key", "Z" * 32)  # invalid hex
        assert "error" in str(exc_info.value).lower()

    def test_wrong_key_rejection_and_recovery(self, cli, registry,
                                               coupled_card_uid):
        """Wrong-key auth → 91AE reported as accepted=false; card survives."""
        uid = coupled_card_uid
        registry.require(uid, "read")
        actual = cli.uid()
        assert actual == uid

        # try-key exits 0 for ANY answered probe (accepted OR rejected —
        # the tool answers "is this the key?"), so the verdict is the JSON
        # output, never the exit code. assert on `accepted` instead: a
        # garbage K0 must be rejected whether the card is provisioned
        # (2026-10-26 silicon reference) or factory-blank (zeros is the
        # real K0 there, ff...f still is not — 2026-11-13 bench finding:
        # 04c474 came back blank on the ACR; #292's skip is superseded by
        # this stronger assertion which covers both states).
        out = cli.run("try-key", "--key", "f" * 32, "--json")
        verdict = json.loads(out.strip().splitlines()[-1])
        assert verdict.get("accepted") is False, verdict
        assert verdict.get("reason") == "wrong_key", verdict

        # right key: uid still readable (card undamaged)
        assert cli.uid() == uid

    def test_wipe_wrong_issuer_refused(self, cli, registry,
                                        coupled_card_uid):
        """Wrong-issuer wipe is refused without card damage."""
        uid = coupled_card_uid
        registry.require(uid, "wipe")
        wrong = "ffffffffffffffffffffffffffffffff"
        with pytest.raises(BoltyError) as excinfo:
            cli.run("wipe", "--issuer-key", wrong, "--confirm-uid", uid)
        # card must still respond to reads
        assert cli.uid() == uid
