# Conformance audit: DRY intake mirror of ccid-firmware-rs #134

Status: skeleton (issue #91). This is bolty-rs's intake rulebook for the
conformance-audit program running on **Amperstrand/ccid-firmware-rs**
(umbrella [#134], lanes #135–#143): we **consume their outputs instead of
running a parallel audit** — DRY applies to audit facts the same way it
applies to code. Shared foundation: the Reference-First Doctrine (every
wire byte/timing traces to a citation, locked by a test, confirmed by
experiment — because mock/hardware divergence and guessed protocol
constants are the dominant bug class across the bench).

Role split (formalizes what already exists de facto):

- **ccid-firmware-rs = reader role** (pcscd-facing, transparent relay)
- **bolty-rs = standalone role** (device-driven card provisioning)

Reader/CCID/secure-channel logic is never imported here. Reference
discipline, shared driver forks, bench tooling, and the audit pattern
itself transfer freely — this document is that transfer.

## 1. DRY intake rules — quote-lock vs link vs summarize

Every external fact bolty's code depends on lands in exactly ONE intake
class. The class is a property of the fact's source, not of the reader's
convenience:

| Class | Rule | Governs |
|---|---|---|
| **Quote-lock** | Verbatim quote in `// MARKER:` comments, checked by greatspectations against a pinned text source (`specquotes.toml` + `.github/workflows/spec-quote-drift.yml`). Trap: consecutive `//` lines join into ONE multi-line quote matched against contiguous source text — separate quotes from prose with a blank line. Quotes are verbatim incl. backticks and upstream typos. | Normative text with a canonical markdown source |
| **Link** | Consume as a git dep from the canonical Amperstrand fork, pinned by `rev` (never branch-float — `docs/fork-policy.md`). Never copy into this tree; never restate its constants locally. Protocol facts get quote-locked **in the fork** (the ccid #142 pattern) — single place to be right. | Shared driver/protocol crates |
| **Summarize** | Paraphrase with a cite, in prose/docs only. **NEVER for normative wire facts** — a summary can drift silently; a quote or a byte-exact fixture cannot. | Background, rationale, history |

### Per-layer assignment (the NFC/BOLT-card stack)

| Layer | Source | Intake class | Status |
|---|---|---|---|
| BOLT-card protocol (p/c decrypt+verify, counter, key roles, deterministic derivation, privacy) | boltcard/boltcard `docs/{SPEC,DETERMINISTIC,CARD_PRIVACY}.md` | **Quote-lock** — `BOLT_SPEC` / `BOLT_DET` / `BOLT_PRIV` markers, CI-checked | ✅ live (`specquotes.toml`) |
| NTAG424 / SUN framing + crypto vectors | NXP NTAG424 DNA datasheet, AN12196 — proprietary PDFs, no canonical text source | **Byte-exact fixture vectors** (PDF layer is guarded by fixtures, not quotes). If a PDF fact needs prose in-tree, transcribe verbatim into `docs/quote-sources/*.md` with §/page cites (ccid `UM11495` precedent, drift-check only) | ✅ fixtures live |
| MFRC522 PCD (registers, timing, activation ladder) | `Amperstrand/mfrc522-rs` @ `ai-experiments`, pinned `e9ced1e` | **Link** — quote-locks land fork-side (ccid #142); bolty consumes and deletes any local duplicates | ✅ pinned |
| ISO 14443-4 protocol core (PCD session, S(WTX), R(ACK), chaining) | `Foundation-Devices/iso14443-rs` **upstream direct** @ `216d1b9` (fork retired 2026-10-18, #105; rev-pinned #110); our session API/WTX hook live consumer-side in `crates/iso14443-session` | **Link** — same fork-side/upstream lock discipline | ✅ pinned |
| NTAG424 command layer (Rust API, `Sdm`, LenCap fix) | `Amperstrand/ntag424` @ `ai-experiments`, pinned `02f23f5` (bumped from `afb7238` with the vectors-convergence lane; keep-fork+feed decision recorded in `docs/fork-policy.md` §4) | **Link** — `docs/fork-policy.md` governs upstream flow | ✅ pinned |
| Paywalled ISO 14443 parts | ccid #140 proxy ladder (libnfc + PN532/MFRC522 manuals + EMV Book 1) | **Monitor + consume** — no ISO citation in bolty without a tracked quote in the fork/reference layer | ⏳ follows ccid #140 |
| Sibling boltcard implementations | boltcard/bolt-card-programmer (issue #71), Go boltcard proxy | **Read-only cross-audit** — `Audited <date> against <impl>` comments at the audited site; upstream findings are report-only (CHANNEL rule: agents never post on non-member repos) | ✅ pattern live (2026-08-31 A5 audit) |

Intake invariants:

1. **One fact, one home.** If a constant exists in a canonical fork,
   bolty consumes it; when ccid #142's fork quote-locks land, any local
   duplicated constant here is deleted in the same session (#91 task).
2. **No `vendor/` build-path copies.** The 2026-08-30 fork unification
   removed them; reintroducing one requires the ccid #134 class-2
   justification (patched code that cannot live in a fork dep) and an
   entry in this document.
3. **Quote-only copies need provenance.** If a `reference/` copy is ever
   added, it ships with `reference/README.md`: upstream repo + commit +
   license + what we quote (shape: ccid `dc835bb`). PDF-only authorities
   use transcribed-quote markdown instead (§ quote-lock row above).

## 2. Monitoring list — first-focus upstreams

| Watch | What to watch for | Trigger → bolty action |
|---|---|---|
| ccid [#134] umbrella | CI gate wiring, policy changes | mirror applicable improvements into our `spec-quote-drift.yml` / this doc |
| ccid [#142] NFC/NCI quote-lock | locked tests landing in `Amperstrand/mfrc522-rs` + `Amperstrand/iso14443-rs` | consume the locked facts; delete local duplicated constants; add Bolt-card-specific facts (NTAG 424 DNA / SUN, NDEF) as fork PRs or here with cites — never silent local copies |
| ccid [#140] spec-source policy | proxy-ladder decisions for paywalled ISO 14443 | cite their ladder; never cite ISO without a tracked quote |
| ccid [#143] capture/byte-diff harness | reusable harness artifacts | reuse for burn/wipe evidence (extends our #66) and ACR1252-as-oracle diffs (extends our #86) |
| ccid [#137] timing lane | timeout-arithmetic lessons | audit OUR serial/burn timeouts: any fixed protocol timeout must be ≥ the window the parameters we advertise imply |
| ccid #135/#136/#138/#139/#141 | reader-role domains | monitor-only (role separation) |
| `Amperstrand/mfrc522-rs` | commits on `ai-experiments` past our pin `e9ced1e` | explicit reviewed rev-bump commit (`build(deps): align …`, fork-policy rule 2) + `make difftest` |
| `Foundation-Devices/iso14443-rs` (upstream direct since #105) | commits past `216d1b9` | same bump discipline; fork-policy §2 rule 1 |
| `Amperstrand/ntag424` | commits past `02f23f5` | same |
| boltcard/bolt-card-programmer | fixes to the #71 findings (A5-2 compressed-prefix offsets, A5-4 `indexOf p=` false-match) | awareness + cross-impl parity notes; **never push upstream** (report-only, CHANNEL rule) |
| boltcard/boltcard (spec repo) | edits to SPEC/DETERMINISTIC/CARD_PRIVACY | `spec-quote-drift.yml` catches quote drift against a fresh clone; re-audit affected normative lines |

Cross-post rule (issue-truth, from ccid #134): when bolty consumes a
lane output, post the evidence comment on that ccid lane issue **in the
same session** — evidence, not silence.

## 3. Audit checklist skeleton

One copy of this checklist per audited surface, per pass (record in the
lane's tracking issue; statuses cite commit hashes, never "should work"):

```text
[ ] Surface: <name>                      # e.g. serial framing, burn APDU sequence, SDM URL template
[ ] Constants sourced: every protocol constant maps to quote-lock | fork-link | fixture
                       (grep hex literals: MFRC522 regs, ISO 14443 codes, framing bytes)
[ ] No unsourced magic numbers remain (sourced or flagged with an open issue)
[ ] Quotes: strict coverage for MUST-lines we implement; drift-only for reference context
[ ] Fixtures: byte-exact against datasheet vectors (NXP PDF layer)
[ ] Timeouts: fixed value ≥ window implied by advertised parameters (ccid #137 arithmetic)
[ ] Retry budget: card-facing retries bounded; circuit breaker + card-inventory
                   discipline honored — no blind retries on write/auth-budgeted cards (ccid #127)
[ ] Bench confirmation: host suite → `make difftest` → `make test-hil` →
                         burn cycle `tools/hil/burn_cycle.py` (labgrid path: `make test-hil-lg`)
[ ] Findings cross-posted to the ccid lane issue if a shared fact was consumed/changed
```

Verification pyramid (bolty entry points, cheapest first — a lane is
never closed by host tests alone):

1. Host suite: `cargo test --workspace --exclude bolty-esp32`
2. Differential: `make difftest` (66/66) / `make difftest-quick` (46/46)
3. HIL fast path: `make test-hil` (ACR-only; safe while the stick runs nucula)
4. Full burn→tap→wipe cycle: `tools/hil/burn_cycle.py` (percard: `--percard`)

## 4. Wiring against issue #91's task list

- [x] DRY intake rules — this doc §1
- [x] Monitoring list for first-focus upstreams — §2 (mfrc522-rs,
      iso14443-rs, bolt-card-programmer per #71, ccid lanes)
- [x] Audit checklist skeleton — §3
- [x] specquotes.toml pattern + CI step — already live in this repo
      (`specquotes.toml`, `.github/workflows/spec-quote-drift.yml`);
      #69 dogfooding of MUST-line coverage is tracked on #69
- [ ] `reference/README.md` index — create when the first quote-only
      copy lands (provenance shape: ccid `dc835bb`)
      **2026-10-19: condition checked — no `reference/` and no
      `docs/quote-sources/` exists yet; correctly not created**
      (determination recorded on ops #19)
- [x] Protocol-constants sweep (MFRC522 registers, ISO 14443 codes,
      serial framing) — first pass 2026-10-19:
      `docs/protocol-constants-sweep.md` (no unsourced production
      constant; 3 findings: F1 ISO-citation ladder + upstream `crc_a`
      `pub(crate)`, F2 test-only register mirrors, F3 serial-doc drift
      check unwired)
- [ ] Consume ccid #142's fork quote-locks + delete local duplicates —
      blocked on that lane landing **(2026-10-19: still blocked — fork
      feeding is owner-parked, see `docs/nfc-fork-feeding/LEDGER.md`
      decision checkpoint)**

[#134]: https://github.com/Amperstrand/ccid-firmware-rs/issues/134
[#137]: https://github.com/Amperstrand/ccid-firmware-rs/issues/137
[#140]: https://github.com/Amperstrand/ccid-firmware-rs/issues/140
[#142]: https://github.com/Amperstrand/ccid-firmware-rs/issues/142
[#143]: https://github.com/Amperstrand/ccid-firmware-rs/issues/143
