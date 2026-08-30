# Fork Policy — NFC Vendor Crates

## Overview

bolty-rs (and ccid-firmware-rs) carry three vendored NFC crates as private
forks under the Amperstrand org. This document is the single source of truth
for where each fork lives, how consumers depend on it, what license each
fork carries, and how changes flow toward upstream.

Status: **canonical** (2026-08-30). Closes the fork-strategy issues
mfrc522-rs#1, iso14443-rs#6, ntag424#4.

---

## 1. Canonical source: private forks on `ai-experiments`

Each fork's `ai-experiments` branch (the repo default branch) is the
**canonical source**. It is the integration branch all downstream projects
build against, and it carries the licensing documentation for the fork.

| Crate | Fork repo | Upstream | Role |
|---|---|---|---|
| `mfrc522` | `Amperstrand/mfrc522-rs` | crates.io `mfrc522` v0.8.0 (SPI-only) | I2C transport + ESP32 timing patches + bounded wait loops |
| `iso14443` | `Amperstrand/iso14443-rs` | `Foundation-Devices/iso14443-rs` | ISO 14443-4 protocol core: PCD session, S(WTX), R(ACK), chain recovery |
| `ntag424` | `Amperstrand/ntag424` | `jannschu/ntag424` (Codeberg) | NTAG424 DNA command layer: `Sdm::disabled()`, LenCap=0x03 fix |

History: bolty-rs and ccid-firmware-rs each carried divergent in-tree
vendor copies. 2026-08-30 they were unified onto these three forks as the
one canonical source (mfrc522 `e9ced1e`, iso14443 `268db79`).

## 2. Consumers ALWAYS pin by rev — never branch-float

Workspace dependencies pin the exact commit:

```toml
ntag424   = { git = "https://github.com/Amperstrand/ntag424.git",   rev = "6f39a4772b6fa41909fe826c36a624b241a482aa", ... }
mfrc522   = { git = "https://github.com/Amperstrand/mfrc522-rs.git", rev = "e9ced1e", ... }
iso14443  = { git = "https://github.com/Amperstrand/iso14443-rs.git", rev = "268db79", ... }
```

Rules:

1. **`rev = <full-or-fixed-sha>`, never `branch = ai-experiments`.**
   `ai-experiments` is a moving integration branch; a build of a tagged
   release or a known-good firmware stamp must resolve to the same bytes
   forever.
2. **Bumping a rev is an explicit, reviewed commit** (`build(deps): align
   <crate> to canonical fork rev <sha>`) — see 0ee0719 for iso14443
   `268db79`.
3. **Branch-float is not hypothetical**: the fork-strategy issues
   originally documented `branch = "ai-experiments"` pins; while writing
   this policy, mfrc522's `ai-experiments` advanced past `e9ced1e` (a
   gitignore chore, `1dd9f8d`) 62 seconds after the pinned fix landed —
   any branch-floating consumer built after that resolved to a different
   tree.
4. **Today's pins** (2026-08-30), each landing with a fix that motivated
   the unification:
   - `mfrc522` @ `e9ced1e2acc5a724cc0da4f2be6cf4968dc92aff` — software
     iteration cap on MFAuthent/transceive wait loops (a missing hardware
     timer can no longer hang the driver); unifies the divergent vendor
     copies.
   - `iso14443` @ `268db7945ea9486f73df47a36533fcdc4c1301b8` — PCD
     session extraction, S(WTX) timeout extension, R(ACK) block-number
     fix, chain recovery, lint/dep pinning.
   - `ntag424` @ `6f39a4772b6fa41909fe826c36a624b241a482aa` —
     `Sdm::disabled()`, LenCap=0x03 wire-form fix, FS_RESET parity tests.

## 3. Licensing per fork (fields VERIFIED 2026-08-30)

Every field below was read from the pinned checkout, not assumed.

### mfrc522-rs — `MIT OR Apache-2.0`

- `Cargo.toml` @ `e9ced1e`: `license = "MIT OR Apache-2.0"`
- Repo root: `LICENSE` ("MIT OR Apache-2.0") + `LICENSING.md`
- `repository = "https://github.com/Amperstrand/mfrc522-rs"`
- Upstream (crates.io `mfrc522` 0.8.0) is MIT OR Apache-2.0; the fork
  adds no license terms. Compatible with all Amperstrand consumers.

### iso14443-rs — `GPL-3.0-or-later` (Foundation-Devices derivative)

- `Cargo.toml` @ `268db79`: `license = "GPL-3.0-or-later"`
- `Cargo.toml` SPDX header: `© 2025 Foundation Devices, Inc.
  <hello@foundation.xyz>` / `SPDX-License-Identifier: GPL-3.0-or-later`
- Repo root: `LICENSE` (GNU GPL v3 full text) + `LICENSING.md`
- `repository = "https://github.com/Foundation-Devices/iso14443-rs"`
  (upstream origin; the Amperstrand repo is the fork)
- Consequence: bolty-rs is GPL-3.0-or-later (matches), and no
  proprietary-linked consumer may take this crate. See the fork's
  `LICENSING.md` for the dependency-chain analysis.

### ntag424 — `MIT OR Apache-2.0` (jannschu upstream)

- `Cargo.toml` @ `6f39a47`: `license = "MIT OR Apache-2.0"`
- Repo root: `LICENSES/MIT.txt` + `LICENSES/Apache-2.0.txt` (REUSE
  layout) + `LICENSING.md`
- `repository = "https://codeberg.org/jannschu/ntag424"`
- Inherited unchanged from upstream. Compatible with GPL-3.0-or-later
  bolty-rs.

## 4. Upstream contributions: `upstream/*` pointers, never blocking

Contributions back to the true upstreams are prepared as **pointer
branches** in each fork — `upstream/<topic>` pointing at the exact
`ai-experiments` state that is ready to send:

| Fork | Pointer branch | Points at | Topic |
|---|---|---|---|
| `iso14443-rs` | `upstream/pcd-session` | `268db79` | PcdSession extraction (+ S(WTX), R(ACK), chain-recovery stack) |
| `iso14443-rs` | `upstream/wtx` | `268db79` | S(WTX) timeout extension for NTAG424 DNA |
| `ntag424` | `upstream/lencap` | `6f39a47` | LenCap=0x03 wire-form fix (+ `Sdm::disabled()`) |

Rules:

1. Pointers are **created once and never force-pushed** — they mark a
   frozen reviewable state, not a living branch.
2. Upstreaming is **never blocking**: downstream pins move independently
   of whether/when an upstream PR lands. If upstream accepts a change, we
   re-pin to the upstream rev at our own pace.
3. We do not open upstream PRs until the changes are proven in both
   bolty-rs and ccid-firmware-rs on real hardware (per the original fork
   strategy in iso14443-rs#6 / ntag424#4 / mfrc522-rs#1).
