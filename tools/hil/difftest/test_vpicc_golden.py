#!/usr/bin/env python3
"""Replay the golden capture through a real pcsc→vpcd→vpicc round trip.

Starts the golden vpicc on the table-card vpcd slot (35970), connects as a
normal pcsc client, transmits every golden C-APDU, and asserts each answer
is byte-exact (data + SW) against the recording. This is the zero-hardware
analogue of `make difftest-acr`: instead of a burn card on the ACR, the
recorded card answers — so capture-tool/pcsc-stack regressions are caught
without hardware, and the harness has a deterministic reference forever.

Pass criteria: ≥1 exchange executed AND every executed exchange byte-exact
AND no unknown-APDU mismatch recorded by the vpicc.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from vpicc_golden import GoldenVpicc, load_queues  # noqa: E402

# Drives a real pcscd → vpcd (patched Amperstrand driver) → vpicc round
# trip: bench-host environment only. CI runners have no vpcd reader.conf
# entry/driver — the existing env_dependent filter skips it there.
pytestmark = pytest.mark.env_dependent

GOLDEN = HERE / "results" / "golden_acr1252.json"
VPICC_PORT = 35970  # table-card vpcd slot (reader.conf vpicc-table, PATCHED driver)
READER_NAMES = {"vPICC table card"}


def _find_reader():
    from smartcard.System import readers
    for r in readers():
        if any(n in str(r) for n in READER_NAMES):
            return r
    return None


def test_golden_replay_roundtrip():
    atr_hex, queues = load_queues(GOLDEN)
    card = GoldenVpicc("127.0.0.1", VPICC_PORT, bytes.fromhex(atr_hex),
                       {k: v.copy() for k, v in queues.items()})
    card.start()
    try:
        # readiness: first ATR probe served (slot present for pcscd).
        deadline = time.time() + 60
        while not card.answered_probe.is_set() and time.time() < deadline:
            time.sleep(0.5)
        assert card.answered_probe.is_set(), "vpicc never answered an ATR probe"

        from smartcard.Exceptions import NoCardException
        from smartcard.System import readers
        reader = _find_reader()
        assert reader is not None, (
            f"boltcard vpcd reader not found; have "
            f"{[str(r) for r in readers()]}")
        try:
            conn = reader.createConnection()
            conn.connect()
        except NoCardException:
            # pcscd may need a moment after the first ATR probe
            time.sleep(3)
            conn = reader.createConnection()
            conn.connect()

        def _patient_transmit(capdu: bytes) -> bytes:
            # vpcd stall class (skill): right after a pcscd start the slot
            # answers ATR probes but C-APDU delivery can lag ~2 minutes.
            # Transmit in a worker and poll through the window — never
            # fail-fast on a freshly started pcscd.
            import threading
            box: dict[str, object] = {}

            def _tx():
                try:
                    data, sw1, sw2 = conn.transmit(list(capdu))
                    box["r"] = bytes(data) + bytes([sw1, sw2])
                except Exception as e:  # noqa: BLE001 - surfaced in assert
                    box["err"] = repr(e)

            t = threading.Thread(target=_tx, daemon=True)
            t.start()
            deadline = time.time() + 200
            while time.time() < deadline and "r" not in box and "err" not in box:
                time.sleep(1.0)
            t.join(timeout=2)
            assert "r" in box, (
                f"transmit never completed (vpcd stall?): err={box.get('err')}")
            return box["r"]  # type: ignore[return-value]

        sent = exact = 0
        for capdu, answers in queues.items():
            if capdu[:2] == b"\xff\xca":
                # GET-UID pseudo-APDU: answered by the READER driver, not
                # the card — vpcd will not forward it (manual-probe
                # evidence: every real APDU round-trips, FFCA errors).
                continue
            if len(capdu) < 4:
                # 1-byte protocol markers recorded by the capture ('00',
                # 'ff') — not C-APDUs; pcsc rejects them client-side.
                continue
            for _ in range(len(answers)):
                expected = answers.popleft()
                got = _patient_transmit(capdu)
                sent += 1
                if got == expected:
                    exact += 1
        assert sent >= 1, "no golden exchanges executed"
        assert exact == sent, (
            f"{sent - exact}/{sent} exchanges deviated from golden")
        assert not card.mismatches, (
            f"vpicc saw unknown APDUs: {card.mismatches[:4]}")
        assert len(card.apdus_seen) == sent, (
            "pcscd short-circuited some transmits (reader-side handling)")
    finally:
        card.stop()
