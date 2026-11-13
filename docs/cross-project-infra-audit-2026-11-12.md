# Cross-project infrastructure audit — 2026-11-12

Scope: labgrid integration + testing infrastructure across the Amperstrand
repos present on ai-legion (bolty-rs, ccid-firmware-rs, conwrt-bench,
tollgate-lab, prta-labgrid, wallet-matrix/cashu-nfc-matrix, nucula,
micronuts, microfips, ntag424/-vectors/-crypto, virtualboltcard,
boltcard-hce, boltcard-cloudflareworker). Method: read-only code/doc
comparison + live read-only bench checks (bench_inventory.py, labgrid
places/resources, SEATS.md). Canon for bench coordination: conwrt-bench
`docs/labgrid-coordination.md` (single source of truth).

## Verified live state (2026-11-12, ai-legion)

- Coordinator .208:20408 healthy (42 resources).
- Seat topology: boards physically on ai-legion-small since the 2026-11-01
  hands window — m5stick socat-bridged back as `ai-legion-nfc/m5stick-usb`
  (data-only), nucula C3 serial re-exported by small as
  `ai-legion-small-nfc/nucula-c3/NetworkSerialPort`. The `nucula-c3` place
  still matches `ai-legion-ccid/nucula/NetworkService` (re-point pending
  owner latch work) → cross-place contention with `ccid-nucula` is EXPECTED.
- `bolty-console*` units on ai-legion are stale (inactive since 10-28 /
  failed — device moved). AGENTS.md updated (PR #281).
- **Disk: root fs 97% (31G free)** — crossed the 90% bench_inventory FAIL
  line. Drivers: /home 300G, containerd 46G, opencode.db 14G (open by all
  concurrent sessions — owner retention decision), /root/src/worktrees 31G.
  A 4G runaway opensearch docker json.log was truncated. Recorded in
  SEATS.md. This is the 2026-10-10 incident class (~31G away).

## Findings implemented same-day (PRs)

| # | Finding | Fix |
|---|---|---|
| bolty-rs #281 | `Makefile test-hil-lg` targeted dead `.221` coordinator; shell wrappers used invented `LABGRID_COORDINATOR` env name (canon: `LG_COORDINATOR`); AGENTS.md seat topology stale | fixed + lessons-learned addendum (the invented env name is how .221 staleness hid for weeks) |
| bolty-rs #282 | difftest golden + generated fixtures had NO integrity lock — a local edit/bad merge silently re-baselines the 66/66 oracle | LOCK + sha256 self-assert test (ntag424 `02f23f5` pattern), runs in host CI |
| bolty-rs #283 | signed bench holds carried mark/sha but no `est=` — the conwrt lock janitor cannot ETA-check bolty lanes | `est=` added (derived from `--reserve-timeout-min`; bench_own 90m) |
| bolty-rs #284 | `BOLTY_ACR_AUTOHEAL=1` restarted pcscd while holding only the SHARED reader role and without draining cross-lane readers | restart now runs under the EX disturbance role (lift reader → EX → restart → restore); peer that won't drain = REFUSED |
| ccid #566 | bench_inventory FAILed every run on (a) the deliberately-phantom nucula-c3 group, (b) nucula-c3 place contention | strict `## PHANTOM:` marker → SKIP; cross-place resource contention parsed from `show` → [HELD] |

## Patterns worth keeping (best-in-class per dimension)

- **Queue discipline**: bolty/ccid are canon-compliant (single live
  `reserve --wait`, never poll-acquire, inherit-not-release). conwrt's
  janitor/churn-watch/bench_queue backstops run only on the coordinator
  host — other repos should at least document them in their bench docs.
- **Soak harnesses**: wallet-matrix `payment_soak.py` error_class tagging
  (rpc/t1/tool owners); nucula `soak.rs` in-loop telemetry + reboot
  persistence checks; bolty overnight `ledger.py` destructive-op budget
  (transport errors never touch card counters — "an unreachable card
  cannot have rejected anything").
- **Vector locking**: ntag424 reference-lock (LOCK + self-asserting test +
  upstream drift_check across consumers) is the reference; microfips'
  sha256-pinned golden pairs + weekly protocol-drift cron are the same
  idea for generated artifacts. bolty difftest golden now locked (#282).
- **Evidence**: bolty/microfips Allure (host-local), wallet-matrix
  "test-films" (JSONL-only regeneration), cloudflareworker/prta Blossom +
  Nostr 30078 publication (survives host churn). Gap: Allure/films don't
  leave the lab hosts.
- **Device-in-CI**: wallet-matrix/nucula self-hosted bench runners
  (workflow_dispatch+schedule ONLY — never pull_request; disjoint crons;
  stale-hold release step). bolty is deliberately manual (difftest policy).

## Recommended follow-ups (not done this session)

> **STATUS 2026-11-13:** items 1, 2, 4 and 6 are DONE — #287 (drift
> audit in `make status`, bench-verified live), #288 (bench-state
> survey artifact), cashu-nfc-matrix #7 + Amperstrand/nucula#48
> (error_class family complete; #48 fork — owner merges), ccid-firmware-rs
> #568 + tollgate-lab #36/#34 (pcscd domain codification + holder-record
> lifecycle + restart-done event fix). Same-day also: #286 phantom-match
> cleanup (bolty-rig re-acquirable), ccid #567 persistence-doc
> correction. Items 3, 5 and 7 remain open.

1. Port `bench_inventory.py`-style config-vs-coordinator drift auditing to
   bolty-rs (bolty has exporter YAML in-repo but no audit loop).
2. bolty HIL: bench-state survey artifact (wallet-matrix matrixctl pattern)
   — record coupled cards/reader inventory per run; plan-gate
   geometry-impossible suites.
3. Publish Allure evidence off-host (Blossom + Nostr, cloudflareworker's
   publish_evidence.py pattern) so bench history survives host re-homes.
4. error_class tagging for nucula soak.rs + wallet-matrix tap_soak (only
   payment_soak has it).
5. vpicc stateful-model ladder (bolty-rs) ported to nucula rig /
   wallet-matrix HCE lane — hardware-free reader state-machine testing.
6. ccid codifies its AGENTS pcscd-restart rule the same way bolty #284
   does (route through the domain lock, not doctrine text).
7. Owner decisions: disk pressure (see SEATS.md 2026-11-12), opencode.db
   retention, nucula-c3 place re-point after latch work, docker log
   rotation for the opensearch container.
