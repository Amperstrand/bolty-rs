# mfrc522 upstream submission packet — owner cover letter

Prepared by [#108](https://github.com/Amperstrand/bolty-rs/issues/108)
(2026-10-19). **Nothing here has been posted externally** — per the
CHANNEL rule (2026-09-06) the owner does all posting to non-member
repositories. This file tells the owner what exists, where to send it, and
what was verified.

## Where to submit (identity corrected 2026-10-19)

- Upstream: **https://gitlab.com/jspngh/mfrc522** — merge requests on
  GitLab, not GitHub PRs. (Source: the 0.8.0 crate manifest's
  `repository`/`homepage` fields. `github.com/jspngh/mfrc522` 404s; the
  docs.rs `japaric/mfrc522` link is stale — tags stop at v0.2.0, 2022.)
- Upstream state: latest commit `0a21f600` 2025-01-04 ("Document that I2C
  is implemented"); last repo activity 2026-09-19; crates.io newest 0.8.0
  (2024-11-24). Read the repo's CONTRIBUTING/AI policy before drafting.
- First: make the feed-vs-retire call (LEDGER.md "Decision checkpoint").
  If RETIRE, this packet becomes the vendoring reference instead.

## What to submit (split from `0004`)

`patches/mfrc522-rs/0004-consolidated-delta-vs-upstream-0.8.0.patch` is
the consolidated semantic delta of the fork vs upstream 0.8.0. Suggested
logical merge requests, smallest first:

1. **fix: software iteration caps on wait loops + test repair** — bounds
   the MFAuthent/transceive wait loops (5000 iters ≈ 1.5 s @ 100 kHz I2C),
   surfaces `Error::Timeout`, std-gates the host-only tests. Uncontroversial
   robustness fix.
2. **feat: public register access API** — `pub mod register` +
   `read_register`/`write_register`/`rmw_register` + `AtqA::as_bytes`.
   Motivation text: PCD-level ISO 14443 framing needs raw register control
   (antenna, timer, CRC, FIFO) which the public API does not expose; this
   is what a CCID/PCD consumer (Amperstrand mfrc522-pcd) drives. Expect
   API-shape discussion.
3. **fix: widen REQA timer reload 25 ms → ~100 ms** (`0x3E8` → `0x0FA0`) —
   cites the Arduino MFRC522 library `PCD_ConfigureDefaults()` precedent;
   25 ms was too short for many cards to answer REQA.

Not for upstream (fork identity): Cargo.toml metadata/`=`-pins, LICENSE/
LICENSING.md, the stray `src/comm/comm/` duplicate, tracked `Cargo.lock`.

**Do not submit an "I2C support" MR** — upstream 0.8.0 already ships I2C
(byte-identical files; upstream commit `0a21f600` documents it). The old
"flagship I2C" framing from the 2026-10-18 ledger was a misattribution.

## Verification transcript (2026-10-19, scratch clones under /tmp — no fork pushes)

- Fork head confirmed via API: `ai-experiments` = `1dd9f8d7707bd5bff95e80f88c77a748c56b6443`
  ("chore: gitignore build artifacts", 2026-08-29T20:47:04Z).
- Series chain: `git apply` of 0001 → 0002 → 0003 (refreshed) on an empty
  tree applies cleanly and the resulting tree equals fork head `1dd9f8d`
  exactly, modulo the fork-side tracked `Cargo.lock` (deliberately
  excluded from the packet).
- Reverse checks at `1dd9f8d`: `git apply --check --reverse` CLEAN for
  0002 and for the refreshed 0003 (0001 cannot reverse-check at head
  because 0003 edits the same files downstream — covered by the series
  chain above).
- Submission artifact: `git apply` of 0004 onto the unpacked upstream
  crates.io 0.8.0 source applies cleanly; the resulting `src/` +
  `.gitignore` equal fork head modulo the excluded stray `src/comm/comm/`.
- Upstream tarball provenance: crates.io API download, sha256
  `543f2c392f438e427aa9009338710434884b0dc95d0c39110f456846be0aa352` ==
  the crates.io registry checksum for 0.8.0 (re-verified 2026-10-19
  during PR review; `Cargo.toml.orig` used as the true manifest for
  diffs).

## Fork-side cleanup candidates (next fork commit, any lane)

- Drop the stray `src/comm/comm/` duplicate directory.
- Fix the stale Cargo.toml description ("forked from upstream SPI-only
  crate" — upstream ships I2C).
- The `target/` history accident (`e9ced1e`→`1dd9f8d`) is documented in
  LEDGER.md; the staged 0003 works around it for submissions.
