"""The burn→lock→tap→gated-wipe→blank regression cycle.

Encodes the 2026-09-01 manual verification (hw-burn-wipe-verify.md) as a
single pytest run — zero LLM involvement:

  1. burn     — deterministic public issuer; asserts the 00E0 access-rights
                lock lands on the real card (issue: 6e6f051 regression)
  2. url      — locked-card read=Free proof + live SDM-mirrored p/c
  3. wipe     — the DET:57-59 pre-verification gate must FIRE on the real
                RF-mirrored p/c ("✓ p/c verified") then complete
                (issue: #72 regression)
  4. diagnose — blank + factory E0EE rights restored (wipe-side regression)
  5. wrong-key wipe — gate/auth refuses a wrong issuer WITHOUT card state
                damage beyond bounded auth attempts (safety regression)

Card safety: registry-guarded (cards.toml), --confirm-uid on every mutation,
deterministic public issuer 0000…0001 only, ends blank.
"""

import re

import pytest

from hil import BoltyCli, BoltyError, CardRegistry

pytestmark = [pytest.mark.hardware, pytest.mark.card_mutation]

ISSUER = "00000000000000000000000000000001"  # deterministic public (B12)
URL_TEMPLATE = "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}"
GATE_PASSED = "✓ p/c verified"
GATE_SKIPPED = "skipping pre-verification"


def _require_card(cli: BoltyCli, registry: CardRegistry, uid: str, op: str):
    registry.require(uid, op)
    actual = cli.uid()
    assert actual == uid, (
        f"wrong card coupled: expected {uid}, got {actual} — refusing "
        "(intermittent coupling? reseat per lessons.md:180)"
    )


@pytest.mark.flaky(reruns=2, reruns_delay=3)
def test_burn_lock_tap_gated_wipe_blank(cli, registry: CardRegistry,
                                          coupled_card_uid, ensure_blank):
    uid = coupled_card_uid
    ensure_blank()  # rerun-safety: wipe to blank if prior attempt half-failed
    _require_card(cli, registry, uid, "burn")

    # ── 1. burn: the 00E0 lock must land on silicon ─────────────────────
    out = cli.run(
        "burn", "--issuer-key", ISSUER, "--url", URL_TEMPLATE,
        "--confirm-uid", uid,
    )
    assert "burned and verified successfully" in out, out

    inspect_out = cli.run("inspect", "--issuer-key", ISSUER)
    rights = _access_rights(inspect_out)
    assert rights.get("write") == "key0", (
        f"access-rights lock regression (expected write=key0/00E0): {rights}"
    )
    assert rights.get("read") == "free", (
        f"read must stay Free for wallet taps: {rights}"
    )
    assert "CMAC_valid=true" in inspect_out, inspect_out

    # ── 2. locked tap: read=Free + genuine SDM-mirrored p/c ─────────────
    live_url = cli.run("url").strip().splitlines()[-1]
    assert re.search(r"[?&]p=[0-9a-fA-F]{32}", live_url), (
        f"no real SDM-mirrored p= in live URL: {live_url}"
    )
    assert re.search(r"[?&]c=[0-9a-fA-F]{16}", live_url), (
        f"no real SDM-mirrored c= in live URL: {live_url}"
    )

    # ── 3. wipe: the #72 gate must fire on the real mirrored p/c ────────
    out = cli.run("wipe", "--issuer-key", ISSUER, "--confirm-uid", uid)
    assert "Pre-verifying p/c (DET:57-59)" in out, (
        f"wipe gate did not run: {out}"
    )
    assert GATE_PASSED in out, f"wipe gate did not pass on real p/c: {out}"
    assert "wiped and verified successfully" in out, out

    # ── 4. diagnose: blank + factory E0EE restored ───────────────────────
    diag = cli.run("diagnose", "--issuer-key", ISSUER)
    assert "Card state:     BLANK" in diag, diag
    rights = _access_rights(diag)
    assert rights.get("write") == "free", (
        f"wipe must restore factory E0EE (write=free): {rights}"
    )
    assert rights.get("change") == "key0", rights


@pytest.mark.flaky(reruns=2, reruns_delay=3)
def test_wipe_wrong_issuer_refused(cli, registry: CardRegistry,
                                   coupled_card_uid, ensure_blank):
    uid = coupled_card_uid
    ensure_blank()
    _require_card(cli, registry, uid, "wipe")

    # Burn a known state first so the refusal is measurable.
    cli.run("burn", "--issuer-key", ISSUER, "--url", URL_TEMPLATE,
            "--confirm-uid", uid)

    wrong = "ffffffffffffffffffffffffffffffff"
    with pytest.raises(BoltyError) as excinfo:
        cli.run("wipe", "--issuer-key", wrong, "--confirm-uid", uid)
    err = str(excinfo.value)
    assert ("authentication failed" in err or "SUN MAC" in err
            or "p= decryption failed" in err), err

    # Card must still be intact under the CORRECT issuer.
    diag = cli.run("diagnose", "--issuer-key", ISSUER)
    assert "PROVISIONED" in diag, (
        f"card damaged by wrong-key wipe attempt: {diag}"
    )

    # Cleanup: leave blank (the lab-stock convention).
    out = cli.run("wipe", "--issuer-key", ISSUER, "--confirm-uid", uid)
    assert GATE_PASSED in out, out
    assert "wiped and verified successfully" in out, out


def _access_rights(inspect_out: str) -> dict[str, str]:
    m = re.search(r"access_rights: AccessRights \{([^}]+)\}", inspect_out)
    if not m:
        return {}
    body = m.group(1)
    out = {}
    for part in ("read", "write", "read_write", "change"):
        mm = re.search(
            rf"{part}: (Free|Key\(Key\d\))", body.replace("read_write", "read_write")
        )
        if mm:
            val = mm.group(1)
            out[part] = "free" if val == "Free" else f"key{val[-2]}"
    return out
