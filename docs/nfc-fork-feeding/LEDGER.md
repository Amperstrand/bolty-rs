# NFC fork-feeding ledger — deltas of the canonical forks vs upstream

Working ledger for [issue #92](https://github.com/Amperstrand/bolty-rs/issues/92)
(coordinates with ccid-firmware-rs #142), refreshed by [#108](https://github.com/Amperstrand/bolty-rs/issues/108)
(2026-10-19) after the iso14443 fork retirement (#105). **Status: staged
in-repo — nothing posted externally** (upstream merge requests are
owner-only actions per the CHANNEL rule 2026-09-06). Every delta below is
exported as a ready-to-submit patch under `patches/`.

Consumption pins (this repo's `Cargo.toml`, post-#105/#110):
`mfrc522 @ Amperstrand/mfrc522-rs e9ced1e` (fork head `1dd9f8d`) ·
`iso14443 @ Foundation-Devices/iso14443-rs 216d1b9` — **upstream direct,
fork RETIRED by #105** · `ntag424 @ Amperstrand/ntag424 afb7238`.

Classification key: **FORK-SHARED** = generic MFRC522/ISO-14443 wire fact,
belongs in the canonical repo (feed the fork); **BURNER-LOCAL** = Bolt Card /
NTAG 424 DNA surface, quote-locked here per `specquotes.toml`; **HYGIENE** =
repo mechanics, no wire meaning.

## Amperstrand/mfrc522-rs (`ai-experiments`, vendored from crates.io `mfrc522` 0.8.0)

Fork history: `84f4f29` (root: vendored 0.8.0 + patches) → `bc3ebfb`
(metadata) → `e9ced1e` (caps; this is the workspace pin) → `1dd9f8d`
(gitignore; fork head).

**Delta table — re-derived empirically 2026-10-19 (#108) by diffing the
fork tree against the unpacked upstream crates.io 0.8.0 tarball.** This
corrects the 2026-10-18 table, which misattributed the I2C transports to
the fork (see correction note below the table).

| # | Delta (fork vs upstream 0.8.0) | Class | Consumed by bolty-rs? |
|---|---|---|---|
| 1 | **Public register API**: `pub mod register` + `pub use register::Register`, `read_register`/`write_register`/`rmw_register` on the driver, `AtqA::as_bytes()` | FORK-SHARED — API proposal-grade; a PCD-layer consumer needs raw register access | **YES — load-bearing**: `crates/mfrc522-pcd` (21 call sites: `Register`, all three accessors); `AtqA::as_bytes` unused |
| 2 | **REQA timer reload widened**: `TReloadReg` 0x3E8 (25 ms) → 0x0FA0 (~100 ms), comment cites Arduino MFRC522 `PCD_ConfigureDefaults()` | FORK-SHARED — behavioral fix; upstream 25 ms too short for many cards | YES — activation window on the bench rig |
| 3 | **Software iteration caps** on MFAuthent/transceive wait loops (5000 iters ≈ 1.5 s @100 kHz) replacing infinite hangs; `Error::Timeout` surfaced; eh02 test repair + std-gating; expanded test expectations (`e9ced1e`) | FORK-SHARED — robustness fix any consumer wants | **YES** — `bolty-mfrc522` maps `Mfrc522Error::Timeout` into retryable activation errors |
| 4 | Cargo.toml: description ("forked from upstream SPI-only crate" — **stale claim, see correction**), repository → fork URL, `=pinned` deps, `[lib]` section (`bc3ebfb` + vendoring) | HYGIENE | fork identity only |
| 5 | LICENSE (dual text) + LICENSING.md (`bc3ebfb`) | HYGIENE | — |
| 6 | `.gitignore` `/target`, `/Cargo.lock` (`1dd9f8d`) | HYGIENE | — |

**Correction (2026-10-19): I2C is NOT a fork delta.** The fork's
`comm/blocking/i2c.rs` and `comm/eh02/i2c.rs` are byte-identical to the
upstream crates.io 0.8.0 tarball, and upstream's own history documents it
(GitLab commit `0a21f600` "Document that I2C is implemented", 2025-01-04).
The 2026-10-18 ledger row "I2C transport support (upstream 0.8.0 is
SPI-only) — the flagship upstream candidate" was a misattribution; there is
no I2C gap to feed. The fork's real flagship is the register access API
(row 1) — exactly what a PCD/CCID consumer (`crates/mfrc522-pcd`) needs.

**Upstream identity — corrected 2026-10-19:** the crate's true home is
**`https://gitlab.com/jspngh/mfrc522`** (Cargo.toml `repository`/`homepage`
fields in 0.8.0). `github.com/jspngh/mfrc522` does not exist (404; the
2026-10-18 plan recorded that GitHub path in error) and docs.rs's link to
`github.com/japaric/mfrc522` is stale (that repo's tags stop at v0.2.0,
last push 2022-03-25; `japaric` is the original co-author). Upstream
activity (GitLab API, 2026-10-19): latest commit `0a21f600` 2025-01-04;
last repo activity 2026-09-19; no GitLab releases. crates.io newest is
0.8.0 (2024-11-24). Upstream is slow but not dead — a feed attempt is
plausible, unlike the pre-correction "dormant ~2 y" reading.

Fork-side hazards (unchanged):
- ⚠ the fork's history accidentally commits `target/` (`e9ced1e` added it,
  `1dd9f8d` untracked it) — raw `format-patch` of those two commits is
  unusable for submission; the staged 0003 patch is the semantic delta only.
- ⚠ stray `src/comm/comm/` duplicate directory rides in the fork tree
  (accidental; excluded from 0004, flagged for fork-side cleanup).

Packets under `patches/mfrc522-rs/` (all verified 2026-10-19, see
`COVER.md` for the verification transcript):
- `0001` + `0002` + `0003` — the fork's own history, staged as a series:
  0001 is the root-commit vendored tree (3675 lines), 0002 the metadata,
  0003 the semantic `e9ced1e`+`1dd9f8d` delta (src/ + `.gitignore`,
  refreshed by #108 to fold in `.gitignore` so the series reproduces the
  `1dd9f8d` tree exactly, modulo the fork-side `Cargo.lock`).
- `0004` — **the submission-grade artifact**: consolidated diff of fork
  head vs upstream 0.8.0 source (register API + timer widening + caps +
  test repair + `.gitignore`). This is what the owner splits into logical
  upstream merge requests.

## Amperstrand/iso14443-rs — RETIRED (superseded by #105 + #110)

The fork and its staged feeding patches are **superseded**: #105
(`45d3d9f`, 2026-10-18) retired the Amperstrand fork and moved consumption
to Foundation-Devices upstream direct (rev-pinned `216d1b9` by #110); the
remaining deltas (PcdSession, TimeoutExt S(WTX), Rule-5 chain recovery)
live consumer-side in `crates/iso14443-session` on the public upstream
API. The five staged patch files (lint-allows, GPL licensing, S(WTX),
chain-recovery re-send, R(ACK) block-number toggle) were deleted from this
directory by #108; upstream natively carries the protocol-correct
R(ACK)/chaining/retransmit/S(WTX) behavior (verified 2026-10-18 via zread
of Foundation-Devices docs). This section is the tombstone — do not
re-stage iso14443 patches.

## bolty-rs usage inventory (fork-shared vs burner-local)

- mfrc522 fork-API call sites: `crates/mfrc522-pcd/src/lib.rs`
  (`mfrc522::{Initialized, Mfrc522, Register, RxGain, comm::blocking::i2c::I2cInterface}`,
  `read_register`/`write_register`/`rmw_register` ×21),
  `crates/bolty-mfrc522/src/lib.rs` (`mfrc522::Error` incl. `Timeout`),
  `apps/bolty-esp32/src/firmware{,/service}.rs` (glue via the bolty crates).
- iso14443: consumed upstream-direct + `crates/iso14443-session` (post-#105).
- FORK-SHARED facts consumed: MFRC522 register-level PCD control, REQA
  timing, bounded-wait discipline.
- BURNER-LOCAL set (stays here, `specquotes.toml` + fixtures): NTAG 424
  DNA SUN authentication offsets/crypto, Bolt Card protocol quotes,
  NDEF wrapping, card-write retry budgets (#92 task 6).

## Decision checkpoint — mfrc522 FEED vs RETIRE (recorded 2026-10-19, #108)

**Status: OPEN — owner decision required.** Not assumed. The 2026-10-18
framing ("upstream dormant ~2 y, retire-path likelier") was based on the
wrong upstream identity and is withdrawn. Evidence as of 2026-10-19:

- **FEED** (post 0004-derived merge requests to `gitlab.com/jspngh/mfrc522`):
  upstream is alive (activity 2026-09-19; I2C maintained and documented);
  the register-API delta is proposal-grade and matches what any PCD/CCID
  consumer needs; caps + timer widening are small uncontroversial fixes.
  If merged and released: re-pin the manifest to the crates.io version,
  drop the fork, done. Risk: MR latency on a low-traffic project; the
  register API may need bikeshedding (`read_register` vs exposing
  `Interface`).
- **RETIRE** (mirror the #105 iso14443 playbook): consume crates.io
  `mfrc522 = "0.8.0"` directly and carry the delta consumer-side. The
  blocker the playbook has to solve here: upstream keeps `mod register`
  private with no raw register access, and `crates/mfrc522-pcd` drives the
  PCD at register level (21 call sites) — so retiring means vendoring the
  register API into a bolty-side crate (e.g. a `mfrc522-reg` extension via
  the public `comm::Interface` + a re-declared register map, or moving the
  PCD framing fully onto `transceive`). Cheap to prototype: the delta is
  one file of API + one constant (`0x0FA0`) + the caps.
- Template: #105 retired iso14443 to upstream-direct + consumer-side
  `crates/iso14443-session` with zero wire regression (364 host tests).
- Either way: nothing changes in the manifests until the owner decides and
  a follow-up lands (this issue stages the packet only).

## Next actions when the owner lifts the no-post rule

1. Confirm the feed-vs-retire call (checkpoint above).
2. If FEED: submit to **GitLab** `jspngh/mfrc522` (merge requests, not
   GitHub PRs), split from `0004`: (1) register access API, (2) timer
   widening, (3) iteration caps + test repair. Read the upstream
   CONTRIBUTING/AI policy first (CHANNEL rule); the owner does the posting.
3. Fix the fork-side warts in the same pass if touching the fork: stray
   `src/comm/comm/`, stale "SPI-only crate" description string.
4. Coordinate sequencing with ccid-firmware-rs #142 so the two consumers
   never double-submit the same change.
