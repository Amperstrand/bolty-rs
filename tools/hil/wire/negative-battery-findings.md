# Negative battery findings — real NTAG424 silicon (2026-10-27)

Source: negative_battery.py (tools/negative/), wire-captured via usbmon
(negative-battery.pcapng, 290 CCID frames). Card: 04C474FA967380 BLANK.
All cases recoverable; budget: 5/50 SeqFailCtr (recovery verified).

## New silicon status codes (first wire capture)

| SW2 | Silicon meaning (empirical) | Context | Applet current |
|-----|---------------------------|---------|----------------|
| 91 7E | unknown/unrecognized command in NXP session | unknown INS 0x77 in CLA 0x90; truncated APDU | 6D00 (ISO, from JCRE) |
| 91 CA | protocol-state violation (e.g. auth attempt after unfinished GetVersion chain; invalid key number K7) | ladder-1 post-GetVersion, key7 | (not mapped) |
| 91 1C | security status not satisfied (NXP space) | SetCardUid without auth; AuthSecond without AuthFirst | 6982 (ISO) |
| 91 BE | boundary error — read offset/length beyond file size | ReadData offset 0x01FFF0 on 416B file | ISO WRONG_LENGTH (6700) |
| 91 F0 | file not found (NXP space) | GetFileSettings on file 0x07 | 6A82 (ISO) |

## Confirmed expected behaviors

| Case | Silicon SW | Notes |
|------|-----------|-------|
| wrong-key AuthSecond (garbage cryptogram) | 91 AE ×4 | clean wrong-key rejections |
| recovery AuthFirst after 4 failures | 91 AF | SeqFailCtr reset-on-success confirmed |
| NTAG INS with ISO CLA 0x00 | 6D 00 | ISO layer rejects before NXP dispatch |
| ISO UpdateBinary on CC file (read-only) | 69 82 | standard ISO security |
| ISO Select (NXP AID) | 90 00 | always works |
| GetVersion (unauthenticated) | 91 AF + 7B data | works on factory card |

## Divergences recorded for the applet (A/B action items)

1. **91F0 vs 6A82** (file not found): silicon uses NXP SW space; applet
   uses ISO SW. Low impact (host tolerates) but should match.
2. **91BE vs 6700** (read beyond EOF): silicon boundary error; applet
   ISO wrong length. Same class of divergence.
3. **917E vs 6D00** (unknown NXP INS): silicon has its own "unknown"
   status; the applet's JCRE returns ISO 6D00. The applet should return
   917E for NXP-CLA unknown INS.
4. **911C vs 6982** (security not satisfied): silicon uses NXP-specific
   security error; applet uses ISO 6982. Should map to 911C.
5. **91CA**: invalid key number returns this on silicon — the applet
   doesn't map it (currently ISO 6982 via generic checks).

## Pyscard→NTAG434 gotchas (documented for future batteries)

- MUST use SCardBeginTransaction (single-transaction holds the NXP
  application layer)
- MUST pin SCARD_PROTOCOL_T1 (NTAG424 = T=CL Type 4)
- All NXP case-4 APDUs need trailing Le=0x00 byte (without it: 917E
  "unknown command" — silent APDU-shape mismatch, not a protocol error)
