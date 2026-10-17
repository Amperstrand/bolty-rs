# NFC fork-feeding ledger — deltas of the canonical forks vs upstream

Working ledger for [issue #92](https://github.com/Amperstrand/bolty-rs/issues/92)
(coordinates with ccid-firmware-rs #142). **Status: staged in-repo — nothing
posted externally** (fork PRs are owner-only actions). Every delta below is
exported as a ready-to-submit patch under `patches/`.

Consumption pin (this repo's `Cargo.toml`):
`mfrc522 @ Amperstrand/mfrc522-rs e9ced1e` ·
`iso14443 @ Amperstrand/iso14443-rs 268db79`.

Classification key: **FORK-SHARED** = generic MFRC522/ISO-14443 wire fact,
belongs in the canonical repo (feed the fork); **BURNER-LOCAL** = Bolt Card /
NTAG 424 DNA surface, quote-locked here per `specquotes.toml`; **HYGIENE** =
repo mechanics, no wire meaning.

## Amperstrand/mfrc522-rs (`ai-experiments`, base = crates.io `mfrc522` 0.8.0)

| # | Commit | Delta | Class | Backing source / quote anchor |
|---|---|---|---|---|
| 1 | `84f4f29` | **I2C transport support** (upstream 0.8.0 is SPI-only): `comm/blocking/i2c.rs` + `comm/eh02/i2c.rs`, register 0x28 addressing, shared `comm` abstraction | FORK-SHARED — the flagship upstream candidate | MFRC522 datasheet §8.1.2 (I²C interface, slave address 0x28, linear register mode); NXP proprietary → **fixture-locked, not quote-locked** (per `specquotes.toml`'s NXP-layer note) |
| 2 | `84f4f29` | Timer reload widened: REQA timeout comment/values 25 ms→~100 ms (`0x3E8`→`0x0FA0`) — "many cards to respond to REQA" | FORK-SHARED | ISO 14443-3 REQA response time (FDT); EMV 4.3 Book 1 timing as free proxy where libnfc is silent |
| 3 | `e9ced1e` | Software iteration caps on wait loops (5000 iters ≈ 1.5 s @100 kHz) replacing infinite hangs; `Error::Timeout` surfaced; eh02 test repair | FORK-SHARED — robustness fix any consumer wants | Datasheet timer semantics; libnfc `iso14443a.c` poll discipline as the independent framing reference |
| 4 | `bc3ebfb` | Licensing metadata (MIT OR Apache-2.0) + crate metadata | HYGIENE | — |
| 5 | `1dd9f8d` | gitignore build artifacts | HYGIENE | — |
| ⚠ | (tree) | **`src/comm/comm/` stray nested directory committed** (duplicate blocking/eh02/mod.rs) — accidental; should be dropped in the next fork commit | HYGIENE (fork-side cleanup candidate) | — |
| ⚠ | `e9ced1e`→`1dd9f8d` | **the fork's history accidentally commits `target/`** (~1M lines: e9ced1e added it, 1dd9f8d untracked it) — the raw `format-patch` of these two is unusable for submission; the staged 0003 patch below is the semantic `src/` delta only | HYGIENE (fork-side: history rewrite or a note to submitters) | — |

Patches: `patches/mfrc522-rs/0001,0002,0003` — 0003 is the **semantic** delta
of e9ced1e+1dd9f8d (src/ only, stray dir excluded; the raw history is unusable
because of the committed `target/`, row ⚠ above). The stray dir rides in
0001's tree — flagged for the fork's own cleanup, not upstream.

## Amperstrand/iso14443-rs (`ai-experiments`, upstream = Foundation-Devices/iso14443-rs; 29 commits, net +767/−2916)

Head commits, newest first; older restructuring commits (PcdSession
extraction `3b453d5`, PICC module `df2e849`, docs/README waves) are the fork's
API surface this repo consumes — documented, not upstreamed as-is (API
changes need the ccid consumer signed off, per #92 non-goals).

| # | Commit | Delta | Class | Backing source / quote anchor |
|---|---|---|---|---|
| 1 | `268db79` | lint allows + `fmt(no-reorder)` + pinned deps | HYGIENE | — |
| 2 | `d3b00b8` | GPL-3.0-or-later licensing + dependency chain documented | HYGIENE (licensing-critical for propagation) | — |
| 3 | `228714a` | **chain recovery re-sends the original block** (I-block chain wedge recovery) | FORK-SHARED — protocol correctness fix | ISO 14443-4 §7.5 chaining/ACK rules; libnfc + EMV proxies for the wording |
| 4 | `c911904` | **R(ACK) block-number toggle before building** — the classic 14443-4 parity bug class | FORK-SHARED | ISO 14443-4 R(ACK) semantics (block number alternation) |
| 5 | `82f706e` | **S(WTX) timeout extension for NTAG 424 DNA** | BURNER-LOCAL-leaning (spec-relevant to all WTX senders but motivated by NTAG424) — propose upstream as generic S(WTX), keep the NTAG424 cadence facts here | ISO 14443-4 S(WTX) §7.4; NTAG424 SUN timing = NXP proprietary → fixture-locked here |
| 6 | `3b453d5`+`df2e849`+older | PcdSession (borrow-free protocol state), PiccTransceiver + loopback, README/docs waves | FORK API SURFACE — consumed via `crates/mfrc522-pcd` + `bolty-mfrc522`; upstreaming = API proposal, ccid co-sign required | — |

Patches: `patches/iso14443-rs/` (commits 1–5 above, one file each, ready for
upstream submission when the owner posts; not posted per the standing rule).

## bolty-rs usage inventory (fork-shared vs burner-local, task 1 of #92)

- Fork-API call sites: `crates/bolty-mfrc522/src/lib.rs` (`mfrc522::Mfrc522Transport::activate`, `mfrc522::Error`), `crates/mfrc522-pcd/src/lib.rs` (PcdTransceiver bridge; documents the chain-wedge class the `228714a` fix addresses), `apps/bolty-esp32/src/firmware{,/service}.rs` (glue).
- FORK-SHARED facts consumed: REQA/anticollision framing, I-block chaining + R(ACK) parity, timeout/cap discipline — all fed by the deltas above.
- BURNER-LOCAL set (stays here, `specquotes.toml` + fixtures): NTAG 424 DNA SUN authentication offsets/crypto, Bolt Card protocol quotes (`BOLT_SPEC` markers vs boltcard docs), NDEF wrapping, card-write retry budgets (per #92 task 6).

## Next actions when the owner lifts the no-post rule

1. mfrc522: submit 0003 (iteration caps) first — smallest, uncontroversial; then 0001's I2C support as the flagship (upstream has an open I2C gap).
2. iso14443: submit R(ACK) toggle + chain-recovery (0004/0003) as correctness fixes against Foundation-Devices; S(WTX) as a feature PR referencing ISO 14443-4 §7.4.
3. Coordinate sequencing with ccid-firmware-rs #142 so the two consumers never double-submit the same quote-lock.
