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
