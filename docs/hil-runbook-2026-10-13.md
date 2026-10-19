# HIL runbook — 2026-10-13 (post-IDF-5.5.5 dry session)

Everything below was prepared DRY on 2026-10-12 (no hardware touched).
Work landed since the last bench session:

- ESP-IDF **v5.5.5** pin (commit 69667dd) + vendored esp-idf-hal (sd.rs
  backport) + `apps/bolty-esp32/build.sh` (CARGO_WORKSPACE_DIR guard, target
  isolation, loud `verify_idf_pin` gate).
- MFRC522 reliability port from ccid-firmware-rs: field-off dwell (50 ms) +
  field-on settle (5 ms) in `mfrc522-pcd::prepare_for_activation_with_delays`,
  activation ladder (4 × prepare→settle→WUPA) in
  `bolty-mfrc522::Mfrc522Transport::activate_with_delays`, wired through the
  service layer with a FreeRtos delay hook.
- `crates/bolty-pn7160` — ntag424::Transport bridge over the shared
  pn7160-nci crate (git dep, rev f2a250b). Host-tested; no firmware wiring
  yet (needs the pn7160_i2c esp transport — future work).
- tools/hil conftest hardening: labgrid place inheritance (fe17ea5 port),
  OSError-guarded path resolution, release-never-inherited.
- New HIL tests: `tests/test_activation_ladder.py` (bench evidence for the
  ladder), `tests/test_conftest_hardening.py` (host-only, already green).

## Pre-flight (before ANY hardware action)

1. **Rig state check** — the M5Stick was reflashed to **nucula** firmware
   (2026-09-09 audit). DO NOT reflash/role-switch without the owner's
   explicit go-ahead — that destroys nucula state (AGENTS.md rig warning).
   ```bash
   python3 /root/src/ccid-firmware-rs/tests/hardware/labgrid/bench_inventory.py
   labgrid-client -p m5stick acquire   # read the console first: `nucula>` prompt = still nucula
   ```
   If the stick still runs nucula → STOP; run only the ACR-side steps below.
2. Bench lock first, always: every pytest session takes it automatically
   (`rig_lock`); manual scripts: `from tollgate_lab import acquire_bench_lock`.
3. Card registry is the contract (`tools/hil/hil/cards.toml`): burn ops only
   for `04c474fa967380` + `04455ffa967380`; `043365fa967380` stays read-only
   (recovery case).

## Phase 1 — ACR1252 only (safe with nucula on the stick)

```bash
cd /root/src/bolty-rs
cargo build -p bolty-cli            # host CLI against the ACR reader
cd tools/hil
python3 -m pytest tests/test_activation_ladder.py -m hardware -v
python3 -m pytest tests/test_bolty_acr.py -v
```

- `test_activation_ladder.py` is the port's bench evidence: 20/20 stable
  uid reads + 5/5 repeatable diagnose. Pre-ladder baseline (if you want a
  before/after number): `git stash` the bolty-mfrc522 change and rerun —
  expect intermittent `uid_or_none()` failures on marginal coupling.

## Phase 2 — stick firmware (ONLY with owner go-ahead, nucula retired)

```bash
cd /root/src/bolty-rs/apps/bolty-esp32
./build.sh m5stick --flash /dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0
# build.sh itself fails loudly if the IDF pin resolves wrong (verify_idf_pin)
```

Then the canonical re-stamp sequence (AGENTS.md KNOWN-GOOD flow):

1. `python3 tools/hil/burn_cycle.py` — burn→inspect→picc→live tap HTTP 200→
   wipe→blank. ALL PASS expected; the dwell+ ladder is on this path now.
2. REST matrix (needs `wifi,rest` build): provision-cert → token →
   401/200 → `/api/status|uid|diagnose|inspect` → job lifecycle (B24-B26).
3. `make difftest-quick` (46/46 in ~2s) after the ccid role flip, then
   `make difftest` full 66/66 if time allows.
4. Button/hwtest interactive pass if a human is at the rig.

## Phase 3 — BLE (only if the 2026-10-12 dry BLE build compiled)

Check the dry-run result first:
`grep BUILD /tmp/opencode/bolty-ble-build.log` or the B30 lesson entry.

If it compiled:

```bash
cd /root/src/bolty-rs/apps/bolty-esp32
./build.sh m5stick-ble --sdkconfig sdkconfig.defaults.ble \
    --flash /dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0
# serial console → `ble` command → advertising visible (nrf Connect),
# GATT read of the read-only whitelist characteristic
```

Expected blockers to watch for (why this was blocked pre-5.5.5): the
esp-idf-svc fork's bt module needed IDF ≥ 5.3 symbols; IDF v5.5.5 ships
them, but the 0.52-generation bt module itself may still mismatch newer
headers — the dry build answers it.

## Phase 4 — labgrid plumbing validation (no card needed)

The conftest inheritance port (fe17ea5) is bench-observable:

```bash
labgrid-client -p bolty-rig acquire    # pre-acquire by hand
cd tools/hil && python3 -m pytest tests/test_burn_lock_wipe.py -m hardware -v
# session must START (inherited place, no refusal) and must NOT release at
# teardown: verify with `labgrid-client -p bolty-rig who` afterwards.
labgrid-client -p bolty-rig release    # manual release after
```

## Exit criteria

- Phase 1 green → ladder port is bench-proven; AGENTS.md KNOWN GOOD stamp
  can carry the MFRC522 dwell+ladder line.
- Phase 2 green → IDF v5.5.5 gets its first hardware KNOWN-GOOD stamp.
- Phase 3 → BLE verdict (either direction) documented in lessons-learned.
- Everything appended to `results/history.jsonl` automatically.

## Session log — 2026-10-19 (bolty-108 lane, post-#121)

- **Phase 1 GREEN** @ `8028932` (pre-#121 tree + the four unblock fixes
  that became PR #121, merged `7fde51d`): activation ladder **20/20** uid
  reads + **5/5** diagnose on registered card `04C474FA967380` (owner
  placed it on the ACR; a J3R180 JavaCard found on the field cannot run
  NTAG paths — set aside); `test_bolty_acr` PASS, bolty-acr phase **4/4**
  commands (uid/inspect/diagnose/picc) — artifact refreshed 3/4 → 4/4.
  Transcript: /tmp/opencode/bolty-108-bench/*.log + /tmp/bolty-audit.log.
  This is the Phase-1 ACR cycle covering the firmware-affecting #117
  (FWT parse) merge per the device-release rule.
- **ACR1252 UN-WEDGED**: the 2026-10-17 firmware-wedge (#101) did not
  reproduce — reader healthy through the full cycle and the rig round-trip
  below. Forensics record stands as the raw-usbfs hazard note.
- **S20 HCE ↔ ACR vertical round-trip PASS** (boltcard-rig #101 leg):
  phone-as-virtual-bolt-card (`com.amperstrand.boltcard.hce`) stacked on
  the ACR antenna → `roundtrip.py` **3/3 PASS** — physical card-tap via
  ACR PICC, bolty-core `picc_parse_url` valid (uid `04C474FA967380`,
  SDM counter 387→388→389 rotating per read), local worker LNURLW HTTP
  200 `withdrawRequest`, tamper negative rejected 403. First RF pairing
  of the S20 leg on the ACR (nucula coil was the original). Cross-ref:
  boltcard-rig RUNBOOK "S20 FE HCE card leg".
- Environment notes: `tollgate-lab` pip-installed --user on the bench
  host (flock layer, #85); `bolty-rig` labgrid place recreated with
  post-consolidation matches (`make labgrid-place` fixed by #121); bench
  worktrees should keep an isolated `target/` — the shared
  /root/.cargo-target binary was overwritten by a concurrent lane twice
  on 2026-10-19.

## Session log — 2026-10-19/20 overnight (bolty-bench-acr-phase1, V1 attempt)

- **V1 (nucula-cycle) NOT GREEN — blocked pre-mutation.** Transcript:
  `/root/bench-evidence/nucula-cycle/v1_run_overnight.log` (+ CHECKPOINTS.md,
  build/boot/gate-probe logs in the same dir; runner hotfix PR #137).
- Staging validation: nucula PN7160 coil **NoCard** (boot-log evidence after
  board restoration); ACR carries an NTAG424 (ATR-verified) whose card session
  is not connectable (PROTO_MISMATCH / internal error at connect — reader
  session-state anomaly, candidate: stale pcscd session or the static
  `acr1252-if0` entry after re-enumeration; needs a fresh check next session).
- **Board recovered from app-brick** (interrupted flash ~20:58, `invalid
  segment length 0xffffffff`) — `board-nucula` from main `af7c449` built
  (heavy, IDF v5.5.5 pin green) and serial-flashed; boots, PN7160/NCI alive.
- **Firmware finding (bolty-rs#115)**: console RX wedges after boot.
- Registry note: `043365fa967380` recovered + re-registered burn-allowed by
  `c12a8d2` — the registry is the contract; gates follow it.
- Zero mutations all window; gates + abort-before-mutation verified on
  hardware; places released clean; broker left stopped (no CCID backend on
  console firmware).
