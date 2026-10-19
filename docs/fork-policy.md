# Fork Policy — NFC Vendor Crates

## Overview

bolty-rs (and ccid-firmware-rs) consume their NFC vendor crates through
**two private forks** under the Amperstrand org plus **one upstream-direct
dependency** (the iso14443 fork was retired 2026-10-18, #105). This
document is the single source of truth for where each crate lives, how
consumers depend on it, what license it carries, and how changes flow
toward upstream.

Status: **canonical** (refreshed 2026-10-19 by #108 — post-#105 reality;
originally canonical 2026-08-30, closing fork-strategy issues
mfrc522-rs#1, iso14443-rs#6, ntag424#4).

---

## 1. Canonical sources: private forks on `ai-experiments` + one direct upstream

Each fork's `ai-experiments` branch (the repo default branch) is the
**canonical source**. It is the integration branch all downstream projects
build against, and it carries the licensing documentation for the fork.

| Crate | Source | Upstream | Role |
|---|---|---|---|
| `mfrc522` | `Amperstrand/mfrc522-rs` (fork) | `gitlab.com/jspngh/mfrc522` (crates.io `mfrc522` 0.8.0, 2024-11-24 — ships I2C since 0.8.0) | Public register access API + REQA timer widening + bounded wait loops (see `docs/nfc-fork-feeding/LEDGER.md`) |
| `iso14443` | **`Foundation-Devices/iso14443-rs` (upstream direct — fork RETIRED #105)** | — | ISO 14443-4 protocol core; our session API/WTX hook live consumer-side in `crates/iso14443-session` |
| `ntag424` | `Amperstrand/ntag424` (fork) | `jannschu/ntag424` (Codeberg) | NTAG424 DNA command layer: `Sdm::disabled()`, LenCap=0x03 fix, key diversification |

History: bolty-rs and ccid-firmware-rs each carried divergent in-tree
vendor copies. 2026-08-30 they were unified onto three forks as the one
canonical source (mfrc522 `e9ced1e`, iso14443 `268db79`). 2026-10-18 the
iso14443 fork was retired (#105, `45d3d9f`): consumption moved to
Foundation-Devices upstream direct, with the fork-only API carried
consumer-side in `crates/iso14443-session` — that retirement is the
template for any future fork retirement.

## 2. Consumers ALWAYS pin by rev — never branch-float

Workspace dependencies pin the exact commit (post-#110 manifest truth):

```toml
ntag424   = { git = "https://github.com/Amperstrand/ntag424.git",   rev = "afb7238516bcf5fac177eba1910565d1dde9354c", ... }
mfrc522   = { git = "https://github.com/Amperstrand/mfrc522-rs.git", rev = "e9ced1e", ... }
iso14443  = { git = "https://github.com/Foundation-Devices/iso14443-rs.git", rev = "216d1b919ca1fd4d30048a1c764f14379137f3c7", features = ["alloc"] }
```

Rules:

1. **`rev = <full-or-fixed-sha>`, never `branch = ai-experiments`.**
   `ai-experiments` is a moving integration branch; a build of a tagged
   release or a known-good firmware stamp must resolve to the same bytes
   forever. (#105 initially landed the upstream-direct iso14443 entry
   without a rev; #110 pinned it — the float window is exactly why this
   rule exists.)
2. **Bumping a rev is an explicit, reviewed commit** (`build(deps): align
   <crate> to canonical fork rev <sha>`) — see 0ee0719 for iso14443
   `268db79`.
3. **Branch-float is not hypothetical**: while writing the original
   policy, mfrc522's `ai-experiments` advanced past `e9ced1e` (a gitignore
   chore, `1dd9f8d`) 62 seconds after the pinned fix landed — any
   branch-floating consumer built after that resolved to a different
   tree.
4. **Today's pins** (2026-10-19):
   - `mfrc522` @ `e9ced1e2acc5a724cc0da4f2be6cf4968dc92aff` — software
     iteration cap on MFAuthent/transceive wait loops. Fork head is
     `1dd9f8d` (gitignore-only child). FEED-vs-RETIRE decision checkpoint:
     `docs/nfc-fork-feeding/LEDGER.md` (#108).
   - `iso14443` @ `216d1b919ca1fd4d30048a1c764f14379137f3c7` —
     Foundation-Devices upstream main HEAD (v0.3.1 lineage), == the
     pre-#110 lockfile entry, so the pin changed zero dependency bytes.
   - `ntag424` @ `afb7238516bcf5fac177eba1910565d1dde9354c` — == fork
     head (idle since 2026-08-31); upstream alignment tracked by #109.

## 3. Licensing per crate (fields VERIFIED 2026-08-30; iso14443 re-verified upstream-direct 2026-10-19)

Every field below was read from the pinned checkout, not assumed.

### mfrc522-rs — `MIT OR Apache-2.0`

- `Cargo.toml` @ `e9ced1e`: `license = "MIT OR Apache-2.0"`
- Repo root: `LICENSE` ("MIT OR Apache-2.0") + `LICENSING.md`
- `repository = "https://github.com/Amperstrand/mfrc522-rs"`
- Upstream (crates.io `mfrc522` 0.8.0) is MIT OR Apache-2.0; the fork
  adds no license terms. Compatible with all Amperstrand consumers.

### iso14443-rs — `GPL-3.0-or-later` (Foundation-Devices upstream, consumed direct)

- Upstream `Cargo.toml` SPDX header: `© 2025 Foundation Devices, Inc.
  <hello@foundation.xyz>` / `SPDX-License-Identifier: GPL-3.0-or-later`
- Repo root: `LICENSE` (GNU GPL v3 full text)
- `repository = "https://github.com/Foundation-Devices/iso14443-rs"`
  (consumed direct since #105; the Amperstrand fork repo still exists as
  an archive of the retired branch but consumes nothing)
- Consequence: bolty-rs is GPL-3.0-or-later (matches), and no
  proprietary-linked consumer may take this crate.

### ntag424 — `MIT OR Apache-2.0` (jannschu upstream)

- `Cargo.toml` @ `afb7238`: `license = "MIT OR Apache-2.0"`
- Repo root: `LICENSES/MIT.txt` + `LICENSES/Apache-2.0.txt` (REUSE
  layout) + `LICENSING.md`
- `repository = "https://codeberg.org/jannschu/ntag424"`
- Inherited unchanged from upstream. Compatible with GPL-3.0-or-later
  bolty-rs.

## 4. Upstream contributions: staged packets + `upstream/*` pointers, never blocking

Contributions back to the true upstreams are prepared in-repo and posted
only by the owner (CHANNEL rule 2026-09-06 — agents never post to
non-member repos; jspngh/mfrc522 on GitLab and jannschu/ntag424 on
Codeberg are both non-member).

| Crate | Staged state | Topic |
|---|---|---|
| `mfrc522` | `docs/nfc-fork-feeding/` (#108): LEDGER + patches 0001–0004 + COVER.md | Register access API, REQA timer widening, iteration caps — split-ready against upstream 0.8.0; upstream = **gitlab.com/jspngh/mfrc522** (corrected 2026-10-19) |
| `iso14443` | **none — retired** (#105) | The old `upstream/pcd-session` / `upstream/wtx` pointer branches in the retired fork are dead; remaining deltas live consumer-side in `crates/iso14443-session` |
| `ntag424` | fork branch `upstream/lencap` → `6f39a47` | LenCap=0x03 wire-form fix (+ `Sdm::disabled()`); fresh Codeberg delta table pending #109 |

Rules:

1. Staged packets and pointers are **created once and never rewritten
   silently** — they mark a frozen reviewable state, not a living branch.
2. Upstreaming is **never blocking**: downstream pins move independently
   of whether/when an upstream MR lands. If upstream accepts a change, we
   re-pin to the upstream rev at our own pace.
3. We do not post upstream until the changes are proven in both bolty-rs
   and ccid-firmware-rs on real hardware (per the original fork strategy
   in iso14443-rs#6 / ntag424#4 / mfrc522-rs#1), and the owner makes the
   feed-vs-retire call first (mfrc522 checkpoint: LEDGER.md, #108).

## 5. Fork lifecycle status (2026-10-19)

| Crate | State | Next step |
|---|---|---|
| `iso14443` | **retired** (#105, #110) — upstream direct, rev-pinned | none (template for future retirements) |
| `mfrc522` | fork consumed @ `e9ced1e`; packet staged (#108); fork head `1dd9f8d` idle since 2026-08-29 | **owner decision: feed vs retire** (LEDGER.md checkpoint) |
| `ntag424` | fork consumed @ `afb7238` (== head) | #109: upstream delta table + alignment decision |
