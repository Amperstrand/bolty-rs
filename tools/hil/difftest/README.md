# Differential Test Harness

Cross-tests ccid-firmware-rs and bolty-rs against a known-good commercial
reader (ACS ACR1252) using golden-reference differential testing.

## How it works

```
Phase 1: Capture golden reference from ACR1252 (commercial, known-good)
Phase 2: Capture test session from your reader (GemPCTwin = ccid-firmware-rs)
Phase 3: Diff the two sessions — any mismatch is a behavioral difference
Phase 4: Generate pytest fixtures from the golden data for regression testing
```

## Quick start

```bash
# 1. Capture golden reference from ACR1252
cd /home/ubuntu/src/bolty-rs
python3 tools/hil/difftest/capture.py \
    --reader "ACR1252" \
    --output tools/hil/difftest/results/golden_acr1252.json

# 2. (After switching M5Stick to ccid mode) capture test session
python3 tools/hil/difftest/capture.py \
    --reader "GemPCTwin" \
    --output tools/hil/difftest/results/test_ccid.json

# 3. Compare
python3 tools/hil/difftest/diff.py \
    --golden tools/hil/difftest/results/golden_acr1252.json \
    --test tools/hil/difftest/results/test_ccid.json

# 4. Generate test fixtures from golden data
python3 tools/hil/difftest/generate_tests.py \
    --golden tools/hil/difftest/results/golden_acr1252.json \
    --output-dir tools/hil/difftest/generated/
```

## Tools

| Tool | Purpose |
|------|---------|
| `capture.py` | Send APDU matrix to a reader, record all traffic as JSON |
| `diff.py` | Compare two sessions, report mismatches with details |
| `generate_tests.py` | Generate pytest fixtures and C headers from golden data |
| `apdu_matrix.py` | APDU test definitions (~40 tests + 20 fuzz cases) |

## APDU test categories

| Category | Tests | What it covers |
|----------|-------|----------------|
| identity | 3 | UID, ATR, reconnect stability |
| iso7816 | 8 | SELECT (MF, AID, invalid), GET RESPONSE |
| ntag424 | 10 | File reads, file settings, invalid offsets |
| ntag424_keys | 3 | Key operations (expect failures) |
| ntag424_sdm | 1 | SDM metadata (expect failure) |
| malformed | 12 | Empty APDUs, bad CLA/INS, Lc mismatch, Le boundaries |
| stress | 3 | Double-select, repeated reads, garbage after valid |
| fuzz | 20 | Deterministic random bytes (seeded) |

## Card safety

All APDUs are read-only or expected-to-fail. No test mutates card state.
The proven-safe envelope is maintained at all times.

## Output format

Each capture produces a JSON document:
```json
{
  "reader": "ACS ACR1252 ...",
  "card_uid": "04c474fa967380",
  "card_atr": "3B 81 80 01 80 80",
  "results": [
    {
      "test_id": "select_mf",
      "apdu_hex": "00A4000C023F00",
      "response_hex": "3F 00",
      "response_bytes": "3f00",
      "sw": "9000",
      "duration_ms": 12.3,
      "success": true
    }
  ]
}
```
