"""Activation-ladder bench evidence (dry port of ccid-firmware-rs 9fd1626
+ 89382e6, 2026-10-12).

SCOPE (Codex PR #93 P2, corrected): this suite drives bolty-cli over
PC/SC — i.e. the ACR1252 reference reader — and is the ladder's
ACCEPTANCE ORACLE (protocol-level stability under repetition). It does
NOT execute the ESP32 firmware's `activate_with_delays` path; firmware
ladder evidence comes from the runbook procedure
(docs/hil-runbook-2026-10-13.md), which flashes the stick and drives
the console/REST service path.

The firmware's activation path now runs: antenna cycle with 50 ms field-off
dwell + 5 ms settle, then up to 4 rounds of (prepare → settle → WUPA) before
giving up. Bench evidence for the port is stability under repetition — the
pre-ladder failure mode (marginal coupling losing REQA/WUPA ~50% of
activations) shows up as intermittent uid timeouts.

Runs against the ACR1252 (PCSC, via bolty-cli) and — when the stick runs
bolty firmware again — the console daemon path. Pure hardware test: marker
`hardware`, needs a registered read-allowed card. NO burn/wipe: read-only.

Run tomorrow (2026-10-13) after the role check:
    cd tools/hil && python3 -m pytest tests/test_activation_ladder.py \
        -m hardware --lg-env labgrid-env.yaml -v
"""

import pytest

from hil import CardRegistry

UID_ROUNDS = 20

pytestmark = [pytest.mark.hardware, pytest.mark.env_dependent]


def test_repeated_uid_reads_are_stable(cli, coupled_card_uid: str, registry: CardRegistry):
    """Every one of UID_ROUNDS uid reads must return the coupled card's UID
    without a transient coupling failure (pre-ladder: ~50% flaky on marginal
    coupling; the ladder's job is to drive that to zero)."""
    registry.require(coupled_card_uid, "read")
    failures = []
    for i in range(UID_ROUNDS):
        uid = cli.uid_or_none()
        if uid != coupled_card_uid:
            failures.append((i, uid))
    assert not failures, (
        f"{len(failures)}/{UID_ROUNDS} uid reads unstable "
        f"(expected {coupled_card_uid}): {failures[:5]}"
    )


def test_diagnose_roundtrip_is_repeatable(cli, coupled_card_uid: str, registry: CardRegistry):
    """diagnose runs a full inspect activation (unauthenticated path): its
    repeat stability covers the RATS half of the ladder."""
    registry.require(coupled_card_uid, "read")
    ok = 0
    for _ in range(5):
        out = cli.run("diagnose", timeout_s=60)
        if "UID:" in out and coupled_card_uid in out.lower():
            ok += 1
    assert ok == 5, f"diagnose stable only {ok}/5 runs"
