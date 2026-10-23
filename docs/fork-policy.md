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
| `iso14443` | **`Amperstrand/iso14443-rs` (fork — RESURRECTED for kernel M2, #174)** | `Foundation-Devices/iso14443-rs` (fork tip descends from upstream main `216d1b9` + additive experiments) | ISO 14443-4 protocol core; the fork carries the in-trait `try_set_timeout_ms` WTX hook that `mfrc522-pcd`'s `PcdTransceiver` needs for cross-repo trait unification (M2, `t_e3335b39`) |
| `ntag424` | `Amperstrand/ntag424` (fork) | `jannschu/ntag424` (Codeberg) | NTAG424 DNA command layer: `Sdm::disabled()`, LenCap=0x03 fix (key diversification is upstream code — see §4 decision record) |

History: bolty-rs and ccid-firmware-rs each carried divergent in-tree
vendor copies. 2026-08-30 they were unified onto three forks as the one
canonical source (mfrc522 `e9ced1e`, iso14443 `268db79`). 2026-10-18 the
iso14443 fork was retired (#105, `45d3d9f`): consumption moved to
Foundation-Devices upstream direct, with the fork-only API carried
consumer-side in `crates/iso14443-session` — that retirement is the
template for any future fork retirement. **2026-10-22: the iso14443
fork was RESURRECTED for kernel M2** (#174, `t_e3335b39`): ccid's
canonical `mfrc522-pcd` depends on the fork's in-trait
`try_set_timeout_ms`, so bolty re-pointed to the fork's rebased
`ai-experiments` tip (`0f7d9d70`, descending from upstream `216d1b9`) to
keep the crate graph unified; `crates/iso14443-session`'s `TimeoutExt`
stand-in retired with it (orphan rule). Same era: bolty's duplicate
local `crates/mfrc522-pcd` was deleted — the crate's canonical home is
now ccid-firmware-rs, consumed here as a rev-pinned git dep.

## 2. Consumers ALWAYS pin by rev — never branch-float

Workspace dependencies pin the exact commit (post-#110 manifest truth):

```toml
ntag424    = { git = "https://github.com/Amperstrand/ntag424.git",      rev = "02f23f51fc352f5abad8812550dc1e0361afe514", ... }
mfrc522    = { git = "https://github.com/Amperstrand/mfrc522-rs.git",   rev = "e9ced1e", ... }
iso14443   = { git = "https://github.com/Amperstrand/iso14443-rs.git",  rev = "0f7d9d70", features = ["alloc"] }  # M2 fork tip — rev MUST stay byte-identical to ccid's pin
mfrc522-pcd = { git = "https://github.com/Amperstrand/ccid-firmware-rs.git", rev = "79456d9947f643bd58a6a8fc4c688ff5bdfe4bc3" }  # canonical home: ccid (kernel M2)
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
4. **Today's pins** (2026-10-20):
   - `mfrc522` @ `e9ced1e2acc5a724cc0da4f2be6cf4968dc92aff` — software
     iteration cap on MFAuthent/transceive wait loops. Fork head is
     `5e4929b` (2026-10-20 upstreamability cleanup: stray `src/comm/comm/`
     duplicate deleted, `Cargo.lock` untracked, manifest corrected — zero
     src/ behavior change, so the pin bump is cosmetic whenever a
     lockfile-touching PR next rides). **Decision 2026-10-20: KEEP** —
     retire is not viable (driver-core deltas); feed parked at owner
     (`docs/nfc-fork-feeding/LEDGER.md`).
   - `iso14443` @ `0f7d9d70` — **Amperstrand fork again** (kernel M2,
     #174): rebased `ai-experiments` tip descending from upstream
     `216d1b9` (v0.3.1 lineage), so the public API is a superset. The
     rev string MUST stay byte-identical to ccid's `crates/mfrc522-pcd`
     pin — a differing string (even short-vs-full of the same commit)
     splits the graph into two `iso14443` copies whose traits stop
     unifying (bench lesson 2026-10-21).
   - `mfrc522-pcd` @ `79456d9947f643bd58a6a8fc4c688ff5bdfe4bc3` —
     canonical home is **ccid-firmware-rs** since kernel M2 (#174);
     bolty's local duplicate was deleted, every consumer
     (`bolty-mfrc522`, `bolty-esp32`, `bolty-stm32`) rides this git
     dep. Same byte-identity rule across every manifest that pins it.
   - `ntag424` @ `02f23f51fc352f5abad8812550dc1e0361afe514` — bumped
     from `afb7238` via #120 (test/docs/reference-lock only, zero
     src-behavior change); fork head remains `02f23f5` (decision record
     §4).

## 3. Licensing per crate (fields VERIFIED 2026-08-30; iso14443 re-verified upstream-direct 2026-10-19)

Every field below was read from the pinned checkout, not assumed.

### mfrc522-rs — `MIT OR Apache-2.0`

- `Cargo.toml` @ `e9ced1e`: `license = "MIT OR Apache-2.0"`
- Repo root: `LICENSE` ("MIT OR Apache-2.0") + `LICENSING.md`
- `repository = "https://github.com/Amperstrand/mfrc522-rs"`
- Upstream (crates.io `mfrc522` 0.8.0) is MIT OR Apache-2.0; the fork
  adds no license terms. Compatible with all Amperstrand consumers.

### iso14443-rs — `GPL-3.0-or-later` (Amperstrand fork; descends from Foundation-Devices upstream)

- Upstream `Cargo.toml` SPDX header: `© 2025 Foundation Devices, Inc.
  <hello@foundation.xyz>` / `SPDX-License-Identifier: GPL-3.0-or-later`
- Repo root: `LICENSE` (GNU GPL v3 full text)
- Consumed from the **Amperstrand fork** again since kernel M2 (#174,
  rebased tip `0f7d9d70`); upstream remains
  `https://github.com/Foundation-Devices/iso14443-rs` — the fork adds no
  license terms
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
| `mfrc522` | `docs/nfc-fork-feeding/` (#108): LEDGER + patches 0001–0005 + COVER.md | Register access API, REQA timer widening, iteration caps — split-ready against upstream 0.8.0; **decided 2026-10-20: KEEP + fork cleaned @ `5e4929b`**, feed parked at owner; upstream = **gitlab.com/jspngh/mfrc522** (corrected 2026-10-19) |
| `iso14443` | **none — fork consumed directly** (M2, #174) | The fork tip is a rebased descendant of upstream main carrying only the in-trait WTX hook M2 needs; no standalone feed packet. The old pre-#105 `upstream/*` pointer branches are dead |
| `ntag424` | fork branch `upstream/lencap` → `6f39a47`; patches 0001–0007 + owner steps durable in-repo at `docs/ntag424-feeding/` (2026-10-23; regenerated after the /tmp wipe, same `f540830..6f39a47` series) | LenCap=0x03 wire-form fix (+ `Sdm::disabled()`); Codeberg delta table + decision done 2026-10-19 (#109) — feed packet staged, ccid co-sign resolved same day, owner post parked |

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

### Decision record — ntag424 (2026-10-19, issue #109)

Research (in-issue, dated 2026-10-19): upstream `jannschu/ntag424`
(Codeberg) main HEAD `f540830` (2026-05-26) **is exactly the fork's
merge-base** — zero upstream commits since; latest release v0.1.1
(2026-05-26, docs.rs-confirmed; newest branch activity anywhere is
`sans-io` @ 2026-06-07). Upstream holds none of our deltas and we hold
none of theirs. Owner decision:

- **KEEP the fork; feed upstream (owner post parked). Re-pin rejected**:
  upstream lacks LenCap=0x03 (AuthFirst wire-form regression) and
  `Sdm::disabled()` (compile break in the wipe path), and pins the
  identical `p224 0.13.2 → ecdsa 0.16 → digest 0.10` chain — re-pinning
  collapses no duplicates. **Retire rejected**: the #105 iso14443
  retirement worked because upstream *had* the fixes; here it has none —
  extraction would freeze them consumer-side with no upstream home.
- **Feed packet staged** (owner-only per rule above, parked at owner
  discretion per "never blocking"): paste-ready Codeberg PR text +
  `git format-patch f540830..upstream/lencap` series. bolty-side
  hardware evidence exists (burn cycles green on the LenCap=0x03 form
  since 2026-06; KNOWN-GOOD stamps 2026-08-27/28). **ccid co-sign
  RESOLVED 2026-10-19 (in-issue record): LenCap=0x03 is independently
  hardware-proven on the ccid side by
  `ccid-firmware-rs/host-tools/boltwipe.py:197`** — AuthEv2First
  `90 71 00 00 05 <keyno> 03 …` (byte-exact bolt-card-programmer port,
  "hardware-proven 2026-08-25, full wipe of a live card" over PC/SC);
  everything else in the packet is N/A-by-structure since ccid-firmware-rs
  consumes no `ntag424` crate (single-consumer fork; its VENDOR_PATCH_AUDIT
  fork layer = mfrc522 + iso14443 only — the earlier ccid#142 pointer was
  a mis-reference). Upstream post is owner-cleared pending only the post
  itself; packet series re-verified applying cleanly to `f540830` on
  2026-10-19.
- **Digest family** (docs/dependency-duplicates.md): the only collapse
  lever is a fork-side p224 refresh; the digest-0.11 generation exists
  only as `p224 0.14.0-rc` (rc.15 2026-06-29, no stable — 0.13.2 is a
  2023 release). **Defer until p224 0.14 stable; re-check quarterly.**
- Correction: **key-diversification is upstream code** (feature since
  ≤v0.1.0; the fork touches no `crypto/`/`high_level/` files), not a
  fork delta — the #109 issue body listed it as one and it had crept
  into the §1 refresh; both corrected.
- Freshness re-checks of the parked feed (authoritative via
  `git ls-remote`, not local clones — local tag lists have twice misled):
  **2026-10-22**: main still `f540830`, all four release tags present
  (v0.1.0-beta1…v0.1.1), no new branches — dormant ~6 months, zero
  delta change; feed packet remains staged, nothing to merge, next
  natural re-check with the p224 quarterly or on any upstream movement.

## 5. Fork lifecycle status (2026-10-19)

| Crate | State | Next step |
|---|---|---|
| `iso14443` | **fork again** — RESURRECTED for kernel M2 (#174, 2026-10-22): rebased tip `0f7d9d70`, rev byte-identical to ccid's pin; the #105/#110 retirement is historical | none (ride with M2 kernel work; byte-identity rule above) |
| `mfrc522` | fork consumed @ `e9ced1e`; **decided 2026-10-20: KEEP** — fork cleaned @ head `5e4929b` (retire not viable: driver-core deltas), feed packet parked | none required — owner GitLab post only if/when desired |
| `ntag424` | fork consumed @ `02f23f5` (bumped from `afb7238` via #120); **decided 2026-10-19: keep + feed, post parked, co-sign resolved** (#109) | owner posts the staged feed packet (only remaining action) |

## Appendix: ntag424 fork-vs-upstream delta table (2026-10-19, refreshed 2026-10-22)

The commit-by-commit classification behind the §4 decision record. Upstream
`jannschu/ntag424` (Codeberg) main HEAD **`f540830`** (2026-05-26) is exactly
the fork's merge-base — upstream has zero commits since (dormant ~6 months,
re-verified 2026-10-22 via `ls-remote` [authoritative; local tag lists have
twice misled on this bench]). The fork carries **100% of the delta**.

Classification key: **FORK-SHARED** = generic NTAG 424 fact, belongs in the
canonical repo (feed upstream) · **BURNER-LOCAL** = Bolt Card surface, stays
Amperstrand-side · **HYGIENE** = repo mechanics.

| # | Commit (date) | Delta | Class | Upstream has it? |
|---|---|---|---|---|
| 1 | `e1dcc0b` (06-16) | AuthEV2First LenCap 0x00→0x03 + 3 zero PCDcap2 bytes, Lc 02→05 (spec-recommended AES-128 encoding; both work on real hardware) | **FORK-SHARED** — wire correctness | **NO** — upstream `aes.rs` still sends `Lc=02 [KeyNo LenCap=00]` |
| 2 | `67488f2` (06-12) | **`Sdm::disabled()`** const ctor — clears SDM on wipe (+16 lines, additive) | **FORK-SHARED** — generic wipe-flow API | **NO** — upstream has adjacent factory-state work but no explicit constructor |
| 3 | — | key-diversification | **NOT a fork delta** — upstream feature since ≤v0.1.0; fork touches zero `crypto/`/`high_level/` files; features block byte-identical | **YES** | 
| 4 | `3fd02f0`+`ee1a874` (merged via fork PR #5) | Auth fixtures regenerated to LenCap=0x03 wire form | test side of #1 | NO |
| 5 | `a25f6c5` (08-27) | ChangeKey byte-exact parity vs bolt-card-programmer, wipe-to-factory K0–K4 (+97, tests) | **BURNER-LOCAL** | NO |
| 6 | `6f39a47` (08-28) | ChangeFileSettings FS_RESET parity (+54, tests; uses `Sdm::disabled()`) | **BURNER-LOCAL** | NO |
| 7 | `7e3a696`+`afb7238`+`02f23f5` (08-30→10-19) | 46-vector cross-language suite vendored + reference-locked (dev-dep `sha2 0.10` only) | **BURNER-LOCAL** — Amperstrand conformance infra | NO |
| 8 | `c862371`, `bc2ef41`, `fa06a22`, `6570c2f`, fork PR #7 | LICENSING.md, fmt, LenCap comment, fork-contract docs | **HYGIENE** | n/a |

**Dependency chain** (the #110 digest-split question): upstream and fork pin
byte-identical dependency lines (`p224 ^0.13.2 → ecdsa 0.16 → digest 0.10`).
Re-pinning upstream collapses NOTHING — the digest family's only 0.10 root is
`p224→ecdsa 0.16` (cmac 0.8 is already 0.11-side). The sole collapse lever
is a fork-side p224 refresh; the digest-0.11 generation exists only as
`p224 0.14.0-rc` (no stable) — **defer until stable, re-check quarterly**.

**Feed packet**: fork branch `upstream/lencap` = upstream HEAD `f540830` +
rows 1/2/4/5/6 rebased (vectors suite deliberately excluded), 30 files
+1051/−108. Regenerate: `git -C <fork> format-patch f540830..origin/upstream/lencap`.
Owner-only post (CHANNEL rule).
