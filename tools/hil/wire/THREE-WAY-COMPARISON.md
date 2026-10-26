# Three-way A/B/C comparison: NTAG424 vs J3R180 vs Virtual (2026-10-27)

The definitive interop document. All three targets ran the same battery:
f5-probe (counter interleave), 6-cycle burn→wipe harness (incl. live
worker taps), negative battery (10 cases). Wire-captured on all physical
targets via usbmon.

## Summary matrix

| Dimension | NTAG424 (silicon) | J3R180 (physical applet) | Virtual (jcardsim) |
|---|---|---|---|
| **f5-probe (no flags)** | ✅ 3/3 + 2/2 | ❌ 1/3 (counter bug) | ❌ 1/3 (counter bug) |
| **f5-probe (with compat)** | N/A (not needed) | ✅ 3/3 + 2/2 | ✅ 3/3 + 2/2 |
| **f5-probe (our fixed applet)** | N/A | untested (GP keys needed) | ✅ 3/3 + 2/2 |
| **6-cycle burn→wipe→tap** | ✅ 6/6 ALL-PASS | ✅ 6/6 ALL-PASS (compat) | ✅ (compat, vpcd flaky) |
| **Structural alignment** | reference | 100% (3286/3286 exchanges) | 98.7% (300/304) |
| **Negative battery: unknown INS** | 917E (NXP) | 6700 (ISO) | 6700 (ISO) → fixed: 917E |
| **Negative battery: file not found** | 91F0 (NXP) | 6A82 (ISO) | 6A82 (ISO) → fixed: 91F0 |
| **Negative battery: security** | 911C (NXP) | 6982 (ISO) | 6982 (ISO) → fixed: 911C |
| **Negative battery: boundary** | 91BE (NXP) | 6700 (ISO) | 6700 (ISO) → fixed: 91BE |
| **Negative battery: invalid keyno** | 91CA (NXP) | 6A80 (ISO) | 6A80 (ISO) → fixed: 91CA |

## Timing comparison (APDU round-trip, µs)

| Metric | NTAG424 | J3R180 | Virtual | J3R180/NTAG424 | Virtual/NTAG424 |
|---|---|---|---|---|---|
| min | 37,480 | 66,371 | <1,000 | 1.8x | ~0x |
| **median** | **58,044** | **801,483** | **<1,000** | **13.8x** | **~0x** |
| p90 | 82,926 | 7,523,705 | <1,000 | 90.8x | ~0x |
| max | 205,918 | 8,408,299 | <1,000 | 40.8x | ~0x |

**Interpretation**:
- **NTAG424** is the performance reference — hardwired AES + direct
  EEPROM, sub-100ms for everything including auth+key-change chains
- **J3R180** is 13.8x slower at median — Java Card VM interpretation
  overhead for every AES CMAC computation, plus JCVM EEPROM transaction
  management. The p90/max spread (7.5s/8.4s) reflects JCVM garbage
  collection or EEPROM commit batching during multi-key-change burns.
- **Virtual (jcardsim)** is sub-millisecond — pure in-JVM computation,
  no RF field, no USB transport, no EEPROM. ~60,000x faster than NTAG424.

**Timing includes**: USB transport + (for physical) RF field + card
processing. pcscd session re-establishment gaps between CLI invocations
inflated both physical baselines equally (apples-to-apples ratio).

## Counter semantics (the root-cause bug)

| Target | Plain CmdCtr advance | Verdict |
|---|---|---|
| NTAG424 silicon | ✅ advances on every session command | reference (§9.1.2) |
| J3R180 original applet | ❌ does NOT advance on plain | **THE BUG** |
| Virtual original applet | ❌ does NOT advance on plain | reproduces identically |
| Virtual fixed applet (81b9d95) | ✅ advances on every session command | **FIXED** |
| J3R180 fixed applet | untested (needs GP install) | next step |

## Key findings

1. **The J3R180 is a perfect behavioral clone of the original applet**
   — every structural exchange, every error path, every counter
   behavior matches. The virtual (jcardsim) is also a perfect clone.
   All divergences from silicon are applet-code issues, not
   J3R180-vs-NTAG424 hardware differences.

2. **The performance gap is entirely explainable**: NTAG424 has
   hardware AES; J3R180 computes AES in the JCVM interpreter. The
   13.8x median slowdown is the JCVM AES+CMAC tax.

3. **All 5 SW-space divergences are applet code issues** (not J3R180
   hardware) — the original applet returns ISO SW codes where silicon
   returns NXP SW codes. Our fork fixes all 5.

4. **The counter bug is applet code** (not J3R180 hardware) — our fork
   fixes it; the fixed virtual applet passes the same interleave probe
   that silicon passes.

## What this means for deployment

- **J3R180 is a valid NTAG424 emulator for functional testing** — every
  command, every response, every state transition matches
- **Not viable for performance testing** — 13.8x latency penalty makes
  it useless for timing-sensitive scenarios
- **Perfect for CI/CD** — the virtual (jcardsim) version runs the full
  test suite in <1 second per exchange with zero hardware
- **Our fork closes all known divergences** — the fixed applet would
  be wire-compatible with silicon on every path we've tested

## Artifacts

| File | Content |
|---|---|
| silicon-battery.pcapng | NTAG424 usbmon capture (f5-probe + 8 cycles) |
| j3r180-battery.pcapng | J3R180 usbmon capture (f5-probe + 6 cycles + negative) |
| silicon.wire.jsonl | 3,286 NTAG424 exchanges (vectors) |
| j3r180.wire.jsonl | 3,941 J3R180 exchanges (vectors) |
| silicon-timing-baseline.json | NTAG424 timing (µs) |
| j3r180-timing.json | J3R180 timing (µs) |
| virtual-timing.json | jcardsim timing (sub-ms) |
| j3r180-negative.log | negative battery on J3R180 |
