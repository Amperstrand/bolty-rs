# Negative battery findings — J3R180 NTAG424-emulation applet (2026-10-27)

Source: /tmp/negative_battery.py run twice against the J3R180 applet
(UID 04337d8aae1790, ACR1252 PICC on ai-legion-small), 2026-10-27 00:06
and 01:01 CET. Both runs byte-identical per case — the applet's negative
path is fully deterministic. Raw logs: bench evidence
`j3r180-overnight-20261027/negative-battery-*.log` (lane copy) — see the
silicon counterpart `negative-battery-findings.md` for the reference side.

Headline: **the applet answers negative-path APDUs in the ISO 6xxx SW
space where silicon answers in the NXP 91xx space.** For robustness
testing the applet is a different personality, not a silicon substitute;
assert on "an error of the right class is returned", never on a specific
9xxx code (this is what tools/hil/tests/test_negative_battery.py does).

## Measured applet SW vs silicon (deterministic across 2 runs)

| Case | Silicon SW | Applet SW (measured) | Note |
|------|-----------|----------------------|------|
| wrong-key AuthSecond (garbage cryptogram) | 91 AE | **69 82** ×5 | applet rejects at ISO security layer — wrong-key 91AE path UNTESTABLE on applet |
| recovery AuthFirst after 5 failures | 91 AF | 91 AF | no 91AD delay; counters behave (5 < 50 SeqFailCtr) |
| AuthFirst RndB freshness | fresh | fresh | non-repeating per attempt AND per session (TRNG ok) |
| AuthFirst invalid key K7 | 91 CA | **6A 80** | |
| truncated AuthFirst (Lc=3 claims 5) | 91 7E | **91 AF + RndB** | applet PROCESSES it (ignores LenCap mismatch) — parsing laxity, silicon rejects |
| unknown INS 0x77 in CLA 0x90 | 91 7E | **67 00** | contradicts the earlier "6D00" belief in the silicon table |
| NTAG INS (F5) with ISO CLA 0x00 | 6D 00 | 6D 00 | matches silicon |
| SetCardUid (0x52) without auth | 91 1C | **69 82** | personality marker: command EXISTS on applet (silicon: not implemented, 6D00) |
| ReadData beyond EOF | 91 BE | **67 00** | applet enforces ISO length before NXP bounds |
| GetFileSettings file 0x07 | 91 F0 | **6A 82** | |
| ISO UpdateBinary on CC file | 69 82 | **6A 81** | function-not-supported vs security |
| AuthSecond cold (no AuthFirst) | 91 1C | **69 85** | |
| GetVersion (sanity INS 60) | 9000 + ver | **91 AF + partial bytes** 04040201001A05 | error SW WITH data — same quirk the burn harness sees as `Version: FAILED Unknown(28160)` (6E00) on the other path |

## Other measured divergences (same soak, f5-probe side)

- **Plain reads advance CmdCtr on the applet** (silicon: they do not).
  Signature: first F5/AD pair after auth succeeds, every following op
  fails with IntegrityError — exactly mimicking the vpcd response-desync
  race. Hosts must run with BOLTY_EMU_COUNTER_COMPAT=1 (bolty-cli now
  prints this hint when the probe fails with the env unset).
- **Production compatibility**: 78/78 full burn cycles including live
  worker taps (boltcardpoc.psbt.me HTTP 200) — the applet's SDM/CMAC
  output is byte-compatible with the production verification path. The
  crypto/data model is silicon-equivalent even where the status-word
  personality is not.
- Soak timing: 25 rounds over 2h23m; round wall-time 328–330 s baseline,
  rounds 7–14 drifted to 363–380 s with ZERO failures or retries — host
  CPU contention signature (sibling lanes on ai-legion-small), not a
  card/reader health signal.
