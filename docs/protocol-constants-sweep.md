# Protocol-constants sweep — first pass (2026-10-19, overnight lane)

Executes the ops #19 tail-3 / conformance-audit §3 checklist for the three
named surfaces (MFRC522 registers, ISO 14443 codes, serial framing) plus
the adjacent ATS/serial-mock fixtures. Method: `grep -E '0x[0-9A-Fa-f]{2,4}'`
per crate, every production literal classified per §1 intake classes
(quote-lock / link / fixture / flag); test-module literals classified only
where they constitute a **duplicate of a canonical fact** (one-fact-one-home
check), not as ordinary test data.

Baseline: `af7c449` (main). Counts at sweep time: mfrc522-pcd 51 literals
(25 unique), iso14443-session 27 (19), bolty-mfrc522 33 (15).

## Surface 1 — MFRC522 PCD registers (`crates/mfrc522-pcd`)

| Constant(s) | Value(s) | Intake class | Source / lock | Status |
|---|---|---|---|---|
| Register names (`Register::TxModeReg` …) | — | **Link** | `Amperstrand/mfrc522-rs` @ `e9ced1e` (`pub mod register`, #108-patched API) | ✅ consumed, no address literals in production code |
| `DEFAULT_I2C_ADDRESS` | `0x28` | Fixture (NXP PDF layer) | MFRC522 datasheet §8.1.2 (I²C slave 0x28); bench-proven (hwtest `i2c 0x28` OK, AGENTS 2026-06-15) | ✅ hardware-locked |
| `CommandReg` soft-reset + idle bit | `0x0F`, mask `0x10` | Fixture (PDF layer) | datasheet CommandReg §9.3.1.6; mock asserts the written bytes | ✅ fixture-locked |
| `reset_frontend` value set | `TxModeReg/RxModeReg 0x00`, `ModWidthReg 0x26`, `TxASKReg 0x40` (Force100ASK), `ModeReg (0x3f & !0b11)\|0b01` | Fixture (PDF layer) | datasheet register tables; mock test `last_write_to` asserts every byte (lib.rs tests) | ✅ fixture-locked |
| Timer prescaler/reload | `0xA9`, `TModeReg 0x80`, reload math vs `0xFFFF` | Fixture (PDF layer) | datasheet §9 timer; timer-arithmetic comment at the site (`f_timer = 13.56 MHz / (2·0xA9+1) = 40 kHz`); test asserts `0x07D0` for 50 ms | ✅ fixture-locked + arithmetic comment |
| CRC enable bits (`TxModeReg/RxModeReg \| 0x80`), `CollReg & !0x80`, `FIFOLevelReg 0x80` (flush) | `0x80` masks | Fixture (PDF layer) | datasheet bit definitions; exercised by every transceive test | ✅ |
| `tx_last_bits & 0x07` | mask | Fixture | datasheet `BitFramingReg` last-bits field width | ✅ |
| ComIrq/Error fallbacks | `0xFF` | local policy | "unreadable ⇒ assume worst" — not a protocol fact | ✅ n/a |
| **Test-module register mirrors** (`COMMAND_REG 0x01` … `T_RELOAD_LOW_REG 0x2D`) | 12 addresses | **Flag F2** | duplicates of the fork's `Register` enum (test-side) | ⚠️ see F2 |

## Surface 2 — ISO 14443 codes (`crates/iso14443-session`)

| Constant | Value | Intake class | Source / lock | Status |
|---|---|---|---|---|
| **CRC_A polynomial/init** | `0x8408` / `0x6363` | **Flag F1** | ISO/IEC 14443-3 Annex B (paywalled). Upstream `Foundation-Devices/iso14443-rs` has the **identical implementation but `pub(crate)`** (verified in every checkout revision: `23e5e33`, `268db79`, `73db6d4`, `8145d9e`, `cec1d8f`) — consumption impossible without an upstream API change | ⚠️ see F1 |
| CRC_A known-answer tests | `(0,0)→A0 1E`, `(12 34)→26 CF` | Fixture | standard ISO CRC_A examples (also in EMV Book 1 as free proxy) | ✅ fixture-locked |
| RATS | `0xE0` | Fixture (ISO layer) | ISO 14443-4 RATS; upstream encodes it privately (`RatsParam`); local literal needed for raw frame build | ✅ cite pending F1's ladder |
| I-block base | `0x02` (no CID/BN0/no chaining) | Fixture (ISO layer) | ISO 14443-4 I-block PCB; per-block toggling tested | ✅ |
| ATS test bytes | `0x72, 0xF0, 0x40…` | Fixture | test data | ✅ |

## Surface 3 — ATS/FWI parse (`crates/bolty-mfrc522`)

All literals live in test modules as interface-byte constructions
(`TA 0x5A`, `TC 0x03`, `TB 0x80` = FWI 8, masks `0x20/0x30/0x60/0x70/0x72`)
with comments citing **libnfc `client/cmdhf14a.c`** as the framing
reference — fixture class, properly comment-cited. Production constants
here are decimal policy values (`ACTIVATION_ATTEMPTS = 4`,
`ACTIVATION_SETTLE_MS = 15`, bench-proven 2026-10-09 ccid ladder). ✅ clean.

## Surface 4 — serial framing (`docs/serial-host-protocol.md` + cli mocks)

`docs/serial-host-protocol.md` (landed via #92 lane, PR #116) is the
**self-owned canonical text** — internal contract, not an external fact:
intake class n/a; the doc's byte-level pins + `mock_transport` byte
sequences (`UID 041065FA967380`, `TI 085BC941`, GetVersion parts
documented as "hardware-captured") are fixture-locked. **Flag F3**: the
doc↔implementation consistency is only enforced where tests exist; a
`specquotes`-style drift check over our own protocol doc is not wired
(low priority — the doc landed with byte-pinned tests on the same PR).

## Findings (filed, not silently kept)

- **F1 — CRC_A + ISO-code citation ladder (tracking)**: ISO 14443-3/4
  literals (`0x8408`, `0x6363`, `0xE0`, `0x02`) carry no tracked citation
  because ISO is paywalled; per §1 they must wait for the ccid #140 proxy
  ladder. Additionally the upstream crate keeps `crc_a` `pub(crate)`, so
  the duplicate is currently unavoidable — if the owner ever makes an
  upstream API request to Foundation-Devices (owner-only), a `pub fn
  crc_a` ask removes this duplicate (mirrors the mfrc522 register-API
  feeding story, `docs/nfc-fork-feeding/LEDGER.md`).
- **F2 — test-module register mirrors (minor cleanup, optional)**:
  `mfrc522-pcd` tests restate 12 MFRC522 register addresses as local
  consts instead of using the fork's public `Register` enum. Test-only,
  zero wire risk; fixing is a 20-line mechanical PR that further shrinks
  the duplicated-fact surface. Not scheduled unless a lane touches the
  crate anyway.
- **F3 — serial-doc drift check (low priority)**: wire
  `docs/serial-host-protocol.md` frames into a self-quote check or accept
  test-pin coverage as sufficient. Parked.

## Verdict

No unsourced **production** magic number on the swept surfaces: every wire
constant is fixture-locked (PDF layer per §1 row 2) or link-consumed
(fork enums). The ISO-citation gap (F1) is the only true open item and is
already structurally tracked (ccid #140 monitor row).

Sweep executed by the overnight research lane 2026-10-19; statuses cite
file:line in the baseline commit above.
