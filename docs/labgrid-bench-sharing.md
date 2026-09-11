# Labgrid Bench Sharing Across Amperstrand Projects

Research snapshot: **2026-09-10** (live coordinator state verified; gm65-scanner
studied at `fa6dc93` + in-flight tree). Purpose: document how the org shares
bench hardware through labgrid, record which project is currently exercising
it, and derive an improvement plan for bolty-rs from the gm65-scanner work.

## 1. The sharing architecture (as deployed)

One bench host (`ai-legion-small`), one shared coordinator, many exporters,
cross-project places. Locked down 2026-09-02 (fips-lab
`docs/bench-testing-playbook.md` §Coordinator topology).

```
coordinator  192.168.13.221:20408        (binds only that address; no mDNS here)
exporters    ai-legion-small             (bolty-rs repo, tools/hil/labgrid-exporter.yaml)
             ai-legion-small-microfips   (microfips repo, tools/hil/labgrid-exporter.yaml)
places       bolty-rig, microfips-bench, gm65-qr-loopback, nucula-rig,
             microfips-<alias> per-board state records (documentation-only)
```

### 1.1 Exporter style: tokens, not tunnels

- **bolty-rs exporter**: the M5Stick is a real `USBSerialPort` (ser2net
  publishes `NetworkSerialPort` on acquire); the ACR1252 is a
  `NetworkSmartcardReader` acquisition token (`id_path` pins the physical
  port; busnum/devnum drift on replug).
- **microfips exporter**: everything is a `BenchSerialToken` — a plain
  `ResourceEntry` riding the flat-scalar fallback. No ser2net, no port
  grabbing while unacquired; **direct device access stays the working path**,
  presence detection is HIL preflight's job (sysfs/udev/pcscd). The
  coordinator-visible entry exists for one thing: **exclusivity**.
  (Root cause: labgrid 26.0 has no exportable generic-USB class and udev
  match dicts cannot cross the coordinator wire — the bolty-rs ACR1252
  discovery, generalized.)

### 1.2 Place semantics: cross-project exclusion by token overlap

Acquiring a place reserves every token it matches, so **token overlap between
places = mutual exclusion between projects**. Live examples:

| Place | Matches | Consequence |
|---|---|---|
| `bolty-rig` | bolty m5stick-serial + acr1252 | excludes other bolty sessions |
| `microfips-bench` | all microfips tokens | excludes other microfips sessions |
| `gm65-qr-loopback` | microfips **cyd-serial + stm32-stlink** | a *different project* reserving microfips bench boards |
| `nucula-rig` | microfips **atom-b-serial** + bolty **acr1252** | excludes microfips AND bolty from that hardware |

Upstream labgrid only rejects a second acquisition of the *same* place
(`bolty-rig` vs `microfips-bench` never contend) and coordinator restarts
wipe in-memory place definitions — hence two standing rules:

- **Idempotent `labgrid-place.sh` per project** (bolty-rs pattern; gm65 and
  microfips adopted it verbatim): re-run after any coordinator restart.
- **BenchLock first, place second, never reversed** (playbook pattern 12,
  the AB-BA rule): a kernel flock (`/tmp/amperstrand-bench.lock` via
  `tollgate_lab.acquire_bench_lock`) taken FIRST by every harness, because
  it is the only layer that excludes same-user sessions across harnesses
  and survives coordinator restarts. bolty-rs adopted this in #85
  (`281e73a`, cross-harness flock-first in `rig_lock`).

### 1.3 The layers above labgrid

| Layer | Answers | Source |
|---|---|---|
| `boards.toml` / `cards.toml` registry | WHAT exists, which ops are ALLOWED (flash/observe, burn/wipe) | fips-lab / bolty-rs `tools/hil/hil/` |
| BenchLock (flock) | WHEN exclusively (cross-session, kernel-enforced) | tollgate-lab, pattern 12 |
| BoardReservation (TTL'd JSON) | WHO booked WHICH board until WHEN | tollgate-lab |
| labgrid place + tags | live board STATE (`firmware=` `test=` `owner=` `ts=`) | fips-lab `note_board_state`, pattern 15 |
| session_registry (+ `lab-kill`) | who is doing what on the host right now | tollgate-lab (replaces `pkill -f`) |

**Enrollment is a five-step bundle** (`hackathon-tooling`
`checklists/bench-enrollment.md`): registry entry → exporter token → state
place + tags → BenchLock in the project's harnesses → playbook pointer in
its AGENTS. Worked example: the Micronuts wallet (2026-09-04), another
project's board the FIPS scenarios observe but never flash.

## 2. Who is currently using labgrid: **gm65-scanner**

Verified live on 2026-09-10 (not inferred):

- Place `gm65-qr-loopback` exists on the coordinator with comment
  "CYD QR source -> GM65 -> F469 async firmware CDC loopback" and tags
  `owner=gm65-scanner`.
- It is *actively testing*: `tools/hil/results/` shows
  `campaign-20260910-105412`, `run-20260910-184256`; the run ledger's last
  entry is 2026-09-10 18:46; the worktree carries in-flight untracked work
  (`tools/hil/ur_e2e.py`, `docs/DESIGN-cdc-diagnostics.md`,
  `docs/issue-drafts/2026-09-10-sustained-load-scan-degradation.md`).
- The rig: a CYD (ESP32 + ST7796) renders QR codes; a GM65 module scans
  them; an STM32F469I-DISCO runs gm65-scanner firmware (sync or async
  build) and reports over USB CDC. The harness drives both ends.

Everything else on the coordinator is idle-but-registered (bolty-rig,
microfips-bench, nucula-rig, the per-board state places): no acquisitions
at snapshot time.

## 3. What gm65-scanner did (the 2026-09-08→10 arc)

The arc worth studying — in order, each step committed separately:

1. **Stimulus-source firmware** (`cyd-qr`): a UART line protocol
   (`QR/QRS/QRP/CLR/ID/DIAG`) that renders arbitrary QR payloads on the
   bench display on demand — including a film-negative (`INV`) mode that
   beat normal rendering. The rig stopped depending on printed paper or a
   human holding a phone; test inputs became *programmable*.
2. **Loopback harness** (bench flock + labgrid place): pytest fixtures
   acquire exclusivity, flash both micros through `boards.toml` gates, and
   — because the F469 is SHARED with the Micronuts wallet — **back up the
   2 MiB flash before every flash and restore it in `finally`**, verified
   by USB product string. Also: `st-flash write` alone wedges the target's
   USB → every write is followed by `--connect-under-reset reset`; CDCs
   are identified by by-id product string, never VID:PID (the sync fw
   shares the wallet's VID:PID/serial).
3. **A green regression gate** (`make test-qr-loopback`, 6/6, ~3.5 min):
   CYD up, scanner connected, byte-exact roundtrips at 3 payload sizes,
   negative control, backup/restore proof. Run before merges.
4. **A characterization campaign** (`make test-qr-campaign`, ~45 min
   unattended): seven fault-isolated experiments — reliability soak,
   QR-size envelope ladder, scan-speed/cadence, settings A/B (which
   *resolved repo issue #11 by measurement*), negative controls,
   wedge-reproduction, randomized jitter net. One flock hold, one CYD
   flash, one STM32 backup per session (economy of scarce operations). A
   wedged experiment records its error and the campaign continues.
5. **Measured limits published** (`tools/hil/LIMITATIONS.md`): hard numbers
   with a cliff — everything ≤53 QR modules decodes, ≥57 never does;
   practical 92-byte frame limit; 7.1 decodes/min sustained; and two
   *unknown-unknowns the soak surfaced*: sustained-load scan-delivery
   collapse (recovery differs per firmware) and a settings-wedge that
   turned out not to reproduce on HEAD.
6. **A bring-along reference client** (`gm65qr.py`): every bench lesson
   encoded as a copyable module (winning render config, no-drain polling,
   ACK-frame sanitizing, stale-buffer consumption, unique payloads to
   defeat the module's 5 s same-barcode delay) — documented as a reference
   *for other Amperstrand projects*.
7. **Issue drafts anchored to evidence**: hardware findings land as dated,
   paste-ready drafts in `docs/issue-drafts/` pointing at the campaign
   artifacts; the owner pastes them upstream (owner-gate rule).
8. **Self-healing in the waits**: a wedged xHCI port is recovered by PCI
   remove/rescan *inside every CDC wait*; labgrid state-tag updates are
   best-effort (a coordinator hiccup mid-campaign must not kill a run).

Cross-pollination context (fips-lab playbook ledger): bolty-rs originated
the tools/hil HIL pattern microfips adapted (#191) and the ACR1252 token
pattern; BenchLock flowed the other way into bolty-rs (#85). The gm65 work
is the third generation of this lineage — and the first built *on* the
cross-project enrollment bundle rather than inventing its own coordination.

## 4. Improvement plan for bolty-rs (from the gm65 study)

Ordered by value ÷ effort. Items 1–3 are directly actionable now; 4–5 need
the rig back; 6–7 are documentation hygiene.

### P1 — Mirror rig state onto the labgrid place (pattern 15) — cheap, do now
bolty-rs harnesses take BenchLock + the place but never `set-tags`. Add a
best-effort `note_rig_state(firmware, test, owner=bolty-rs, ts)` to the HIL
package, called by `test-hil`/`difftest`/`burn_cycle`. Anyone on the bench
(including a nucula or microfips session) can then ask labgrid what the
stick runs, instead of probing serial prompts. This would have made the
2026-09-03 nucula takeover visible as `owner=nucula` on the spot.
**Implemented 2026-09-11: `hil/labgrid_state.py` (`note_rig_state`), called
from conftest `rig_lock`, `burn_cycle.py`, `difftest/e2e.py`.**

### P2 — Per-board state places for bolty hardware — cheap, do now
Create documentation-only places `bolty-m5stick` and `bolty-acr1252`
(`create` + `add-match` on the existing exporter tokens + state-tag
comment), mirroring `microfips-<alias>`. Never acquired; pure state
records. Optionally *enroll* the ACR reader and stick formally via the
five-step bench-enrollment bundle — the stick is already de-facto a
multi-project board (bolty ↔ nucula ↔ ccid role switching), which is
exactly what the bundle exists for.
**Implemented 2026-09-11: `make hil-state-places`
(`tools/hil/labgrid-state-places.sh`) — both places live on the
coordinator.**

### P3 — A shared-stick protocol with nucula (the gm65/micronuts pattern)
gm65's F469 is another project's board; every flash session backs up 2 MiB
and restores it, and the place comment says whose firmware it is. The
bolty stick is now in the same situation (nucula holds it). Before any
bolty return to the stick: dump the full chip (115200 only, NVS-differs
lesson), restore-always in `finally`, flip state tags both ways, and put
the agreement in both repos' AGENTS (the bench-enrollment "their firmware,
their flashes" note style). This turns "DO NOT reflash" prose into a
tooling-enforced, state-visible protocol.

### P4 — Characterization campaign for the bolty rig (`make test-hil-campaign`)
The biggest gap. bolty-rs has pass/fail gates (burn→lock→tap→wipe,
difftest) but no measured-envelope characterization. Port the campaign
shape (one lock hold, fault-isolated experiments, per-experiment JSON +
summary.md, LIMITATIONS.md at the end):
- **E1 lifecycle soak**: N burn→tap→wipe cycles — cycle-time distribution,
  failure modes, counter growth per cycle (replaces "6 in a day, ALL PASS"
  anecdotes with numbers).
- **E2 SDM counter ladder**: tap bursts 1..k on a burn-allowed card;
  verify c= monotonicity and counter increments on every tap (spec MUST
  behavior, measured not assumed).
- **E3 auth-behavior map**: AuthFirst/AuthSecond latency vs SeqFailCtr
  level on a *sacrificial* card (cards.toml op-gated; the 043365 recovery
  card stays read-only) — turns the auth-delay folklore into a curve.
- **E4 reader A/B**: same card, ACR1252 vs stick MFRC522 — read success,
  SDM MAC regeneration rates, timing.
- **E5 negative controls**: wrong-key taps, empty field, mid-read card
  removal — the "honest FAIL" surfaces hardware testing still lacks.
Value: the gm65 soak surfaced two degradation modes no green gate would
ever find; bolty's equivalent unknown-unknowns (long-session MFRC522
drift, PCSC wedge classes, counter edge behavior near wrap) are currently
invisible.

### P5 — Bench-lesson reference client (`hil/bolty.py` → documented module)
gm65's `gm65qr.py` "bring-along" idea applied to bolty: the HIL package's
`BoltyCli` already encodes the lessons (console-daemon-only serial access,
UID-confirm gates, auth-delay keep-trying, dry-run preflight). Document it
as a reference client for other Amperstrand projects driving NTAG424
hardware (ntag424-crypto, boltcard-cloudflareworker, bolt-card-programmer
TS app) — with a README section naming the encoded lessons, gm65-style.

### P6 — Rig LIMITATIONS.md
Consolidate the scattered measured limits into `tools/hil/LIMITATIONS.md`:
espflash 115200-only on the FT232 link, full-dump NVS checksum drift,
DTR-wedge class (B11), coordinator place non-persistence, labgrid bind
address, auth-delay budget mechanics, burn-cycle envelope. One referenced
doc instead of AGENTS.md archaeology. (gm65's LIMITATIONS.md is the
template.)

### P7 — Issue drafts for hardware findings
Adopt `docs/issue-drafts/` for bench findings awaiting owner paste
(evidence-anchored, dated). Minor process win; the owner-gate rule already
exists.

### Already at parity (no action)
greatspectations spec-quote drift CI; BenchLock-first rig_lock ordering
(#85); cards.toml as the ops contract; results/history.jsonl run ledger;
idempotent labgrid-place.sh; the cross-harness HIL pattern itself (bolty
is the origin).
