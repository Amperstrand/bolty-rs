#!/usr/bin/env python3
"""Live golden round-trip with the STATEFUL MODEL as the card (rung 1).

Same exchange set as test_vpicc_golden, but every answer is COMPUTED by
vpicc_model (rules + state) instead of replayed from queues. The golden
capture becomes the model's regression test: 57/57 byte-exact required.
Offline rule gate: check_model_vs_golden.py (no pcscd needed).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from vpicc_golden import GoldenVpicc  # noqa: E402
from vpicc_model import ModelVpicc  # noqa: E402

GOLDEN = HERE / "results" / "golden_acr1252.json"
VPICC_PORT = 35970  # table-card vpcd slot (patched driver)
READER_NAMES = {"vPICC table card"}


def test_model_golden_roundtrip():
    g = json.loads(GOLDEN.read_text())
    atr = (g.get("card_atr") or "").replace(" ", "")
    exchanges = []
    for r in g.get("results", []):
        capdu_hex = (r.get("apdu_hex") or "").replace(" ", "")
        if not capdu_hex or len(capdu_hex) < 8 or capdu_hex.startswith("FFCA"):
            continue
        exchanges.append((bytes.fromhex(capdu_hex),
                          bytes.fromhex(r.get("response_bytes") or "") +
                          bytes.fromhex(r.get("sw") or "6d00")))

    card = GoldenVpicc("127.0.0.1", VPICC_PORT, bytes.fromhex(atr),
                       answerer=ModelVpicc())
    card.start()
    try:
        deadline = time.time() + 60
        while not card.answered_probe.is_set() and time.time() < deadline:
            time.sleep(0.5)
        assert card.answered_probe.is_set(), "vpicc never answered an ATR probe"

        from smartcard.System import readers
        cand = [r for r in readers()
                if any(n in str(r) for n in READER_NAMES) and "00 00" in str(r)]
        assert cand, f"table-card slot not found: {[str(r) for r in readers()]}"
        conn = cand[0].createConnection()
        try:
            conn.connect()
        except Exception:
            time.sleep(3)
            conn = cand[0].createConnection()
            conn.connect()

        import threading

        def _tx(capdu):
            box = {}

            def run():
                try:
                    d, s1, s2 = conn.transmit(list(capdu))
                    box["r"] = bytes(d) + bytes([s1, s2])
                except Exception as e:  # noqa: BLE001
                    box["err"] = repr(e)
            t = threading.Thread(target=run, daemon=True)
            t.start()
            end = time.time() + 200
            while time.time() < end and "r" not in box and "err" not in box:
                time.sleep(1.0)
            assert "r" in box, f"transmit stalled/errored: {box.get('err')}"
            return box["r"]

        sent = exact = 0
        for capdu, expected in exchanges:  # golden ORDER: budget consumes
            got = _tx(capdu)
            sent += 1
            if got == expected:
                exact += 1
        assert sent >= 1, "no exchanges executed"
        assert exact == sent, f"{sent - exact}/{sent} model deviations"
        assert len(card.apdus_seen) == sent, "pcscd short-circuited transmits"
    finally:
        card.stop()
