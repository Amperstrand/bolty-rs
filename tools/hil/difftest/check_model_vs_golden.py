#!/usr/bin/env python3
"""Offline golden-vs-model check: every replayable golden exchange must be
byte-exact through the stateful rule engine (no pcscd needed). This is the
fast rule-correctness gate; test_vpicc_model.py adds the live pcsc round
trip on top. Run: python3 check_model_vs_golden.py [golden.json]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from vpicc_model import Ntag424State, answer  # noqa: E402


def main() -> int:
    golden = Path(sys.argv[1] if len(sys.argv) > 1 else
                  Path(__file__).parent / "results" / "golden_acr1252.json")
    g = json.loads(golden.read_text())
    state = Ntag424State()
    sent = exact = 0
    for r in g.get("results", []):
        capdu_hex = (r.get("apdu_hex") or "").replace(" ", "")
        if not capdu_hex or len(capdu_hex) < 8 or capdu_hex.startswith("FFCA"):
            continue  # specials + FFCA + 1-byte markers: not card C-APDUs
        capdu = bytes.fromhex(capdu_hex)
        expected = (bytes.fromhex(r.get("response_bytes") or "") +
                    bytes.fromhex(r.get("sw") or "6d00"))
        got = answer(state, capdu)
        sent += 1
        if got == expected:
            exact += 1
        else:
            tid = r.get("test_id", "?")
            print(f"DIFF {tid}: {capdu_hex}\n  expected {expected.hex()}"
                  f"\n  got      {got.hex()}")
    print(f"{exact}/{sent} byte-exact through the model")
    return 0 if exact == sent and sent > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
