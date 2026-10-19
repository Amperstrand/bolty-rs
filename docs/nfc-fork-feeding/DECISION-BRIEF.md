# DECISION BRIEF — mfrc522 fork: FEED vs RETIRE

**For**: owner decision (the only open fork-lifecycle checkpoint after
ntag424's keep+feed record, `docs/fork-policy.md` §4).
**Prepared by**: overnight research lane, 2026-10-19. Evidence base:
`docs/nfc-fork-feeding/LEDGER.md` + `COVER.md` + patches 0001–0004
(#108, merged `a02bbcd`), re-verified packet chain. **The owner decides;
nothing is retired or re-pinned by preparing this brief.**

## Current state (2026-10-19)

- Consumption: `mfrc522` @ `Amperstrand/mfrc522-rs` `e9ced1e`
  (fork head `1dd9f8d`, idle since 2026-08-29; pin is head−1, head is a
  gitignore-only child).
- Upstream: **`gitlab.com/jspngh/mfrc522`** (0.8.0 manifest fields; the
  GitHub `jspngh` path 404s — corrected 2026-10-19). crates.io newest
  0.8.0 (2024-11-24, sha256-verified tarball). Upstream repo alive:
  last activity 2026-09-19, latest commit 2025-01-04
  ("Document that I2C is implemented").
- The fork's **entire real delta vs upstream 0.8.0** (empirical tree
  diff, packet 0004): public register API (`pub mod register` +
  `read/write/rmw_register` + `AtqA::as_bytes`) — **load-bearing for
  `crates/mfrc522-pcd` (21 call sites)**; REQA timer reload 25 ms→~100 ms;
  software iteration caps + test repair; metadata/licensing; `.gitignore`.
- **I2C is NOT a delta** — upstream 0.8.0 ships it byte-identical
  (misattribution withdrawn 2026-10-19).

## Option A — FEED (post upstream merge requests, then re-pin)

Post the 0004-derived split to **GitLab** `jspngh/mfrc522`
(owner-only, CHANNEL rule): (1) iteration caps + test repair,
(2) public register access API, (3) REQA timer widening. COVER.md holds
the cover letter and split.

- **Cost**: owner posts 3 MRs; API MR may need shape discussion
  (the exact ask matters to ccid-firmware-rs too — co-sign per #92).
  Latency risk on a low-traffic project (weeks–months).
- **Payoff**: if merged + released, the manifest re-pins to crates.io,
  the fork is deleted, and the register-API maintenance burden moves to
  upstream — the same end-state iso14443 reached via #105, but with
  upstream doing the hosting.
- **Risk**: MRs stall (dormancy signs: ~9 months since last commit);
  we carry the fork indefinitely anyway.

## Option B — RETIRE (mirror the #105 iso14443 playbook)

Consume `mfrc522 = "0.8.0"` from crates.io; carry the delta
consumer-side.

- **The hard part**: upstream keeps `mod register` private with no raw
  register access, and `mfrc522-pcd` drives the PCD at register level
  (21 sites). Retiring means a bolty-side extension crate (e.g. a
  `mfrc522-reg` shim re-declaring the register map over the public
  `comm::Interface`, or moving PCD framing onto `transceive`).
- **Cost**: a design+implementation lane (est. 1–2 sessions: the delta
  is one file of API + one constant + the caps — cheap to prototype,
  but it re-homes ~120 lines of register map we'd then own forever).
- **Payoff**: dependency hygiene NOW (crates.io pin, no fork, no
  feeding latency); full control of the PCD layer timing behavior
  (REQA window) without upstream negotiation.
- **Risk**: we permanently own a parallel register map (drift risk
  against future upstream versions — the one-fact-one-home rule bends
  here, same trade-off `iso14443-session` accepted for CRC_A).

## Recommendation (lane's, non-binding)

**Feed first, retire as the fallback clock**: post MR (1) caps — small,
uncontroversial, upstream-friendly — and MR (2) register API together
this week (owner posts from COVER.md). If nothing merges within the
owner's patience window (suggest 4–6 weeks given upstream cadence),
execute Option B with the shim-crate design. Rationale: Option A's cost
is 30 minutes of owner posting vs Option B's multi-session lane, and
the register-API ask is exactly the kind of contribution that keeps a
dormant upstream alive (it already accepted I2C-style extensions).

## What this brief does NOT change

No manifest edits, no fork pushes, no external posts. The LEDGER
checkpoint stays OPEN until the owner records the call here.
