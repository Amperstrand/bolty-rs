# HIL runbook — 2026-11-14 owner hardware session

Owner-facilitated bench work. Everything here needs hands or owner
decisions; tonight's unattended session prepared and pre-verified the
host-side halves. Estimated total: 60–90 min.

State going in (2026-11-13 night): ACR1252 healthy on ai-legion-small
(ATR ok, both pcscd interfaces listed); `04c474fa967380` found
FACTORY-BLANK on the ACR (registry stale: says provisioned/GemPCTwin);
`ccid-nucula` place held since 2026-11-04 (9 days — flagged in SEATS.md);
m5stick socat-bridged; the pn7160-nucula lane has WIP on small's main
checkout — use a throwaway worktree there (pattern below).

## Phase 0 — preflight (5 min, no RF)

```bash
# on ai-legion:
python3 /root/src/ccid-firmware-rs/tests/hardware/labgrid/bench_inventory.py
export LG_COORDINATOR=192.168.13.208:20408 && labgrid-client who
cat /root/bench/SEATS.md   # check for overnight changes
# on ai-legion-small:
ssh ai-legion-small 'git -C ~/src/bolty-rs worktree add /tmp/bolty-hil-$(date +%H%M) origin/main && cd /tmp/bolty-hil-*/tools/hil && python3 -m hil.labgrid_drift'
```

Decision needed: the `ccid-nucula` hold (root@ai-legion since Nov 4).
If deliberate → re-sign with `~est=`; if stale → `labgrid-client -p ccid-nucula release`.

## Phase 1 — card placement audit + re-burn + open-PR verify (15 min, ACR only)

1. **Audit placement**: for each card in `tools/hil/hil/cards.toml`,
   read the UID on the ACR (`bolty-cli uid`) and the nucula antenna;
   update `reader_hint` + `state` to reality, commit. Known drift:
   04c474 (blank, on ACR).
2. **Re-burn 04c474** (restores the wrong-key fixture):
   `bolty-cli burn --issuer-key 00000000000000000000000000000001 --version 1 --confirm-uid 04c474fa967380`
   then `make test-hil` — expect all green.
3. **Verify open PR bolty-rs#** (`test/wrong-key-output-assert`):
   run `make test-hil` on that branch; the wrong-key test must PASS with
   the JSON assertion on the provisioned card (accepted=false, wrong_key).
   Then merge the PR.

## Phase 2 — HCE battery on the S20 (10 min)

Prereqs (SEATS 2026-11-03 note): the S20's payment default currently
routes the boltcard AID to **benchrelay** — flip it back to the boltcard
HCE app first, or the battery will probe the relay, not the app.

```bash
# phone back-panel flat on the ACR antenna, dev.boltcard.hce in foreground
ssh ai-legion-small 'cd /tmp/bolty-hil-*/tools/hil && bash tests/test_hce_battery.sh'
```

Expected: detection PASS (uid 04996c6a926980), ver/inspect/picc PASS,
try-key K0 ACCEPTED (correct key — costs no budget), keyver PASS.
Any FAIL → capture output + `bolty-console` incident snapshot.

## Phase 3 — M5StickC physical buttons (10 min)

The oldest standing gap (2026-08-28 stamp). Console into the stick
(socat bridge `/dev/m5stick-remote` on ai-legion, or small-side port),
run `hwtest`, press FRONT then SIDE button on prompt. Verify: mode
get/set, NVS persistence across reboot (`crashlog` + reboot + mode).
Update the AGENTS "still not hardware-tested" line afterwards.

## Phase 4 — full difftest (5 min, owner-gated)

`make difftest` (role switch + restore-always, 66/66 expected). This is
the first full run since the golden reference-lock (#282) — a failure in
`test_difftest_golden_lock` means the golden drifted; do NOT regenerate
without reviewing `git diff results/golden_acr1252.json`.

## Phase 5 — nucula-c3 latch + place re-point (10 min)

The seat moved to small 2026-11-01; place still matches the phantom.
One-time re-point (then `make labgrid-place` is idempotent again):

```bash
labgrid-client -p nucula-c3 del-match ai-legion-ccid/nucula/NetworkService
labgrid-client -p nucula-c3 add-match ai-legion-small-nfc/nucula-c3/NetworkSerialPort
python3 /root/src/ccid-firmware-rs/tests/hardware/labgrid/bench_inventory.py  # expect 0 FAIL
```

Requires the ccid-nucula hold resolved (Phase 0) and the physical USB
latch secured (owner hands — it was USB-latch-down at move time).

## Phase 6 — optional: proxy.psbt.me origin revival

Owner-only knowledge: which host runs the Go proxy (Cloudflare tunnel
shows the connector). If revived: differential-test the worker against
the reference `createboltcard`/`wipeboltcard` API (the audit's
cross-implementation table is in boltcard-cloudflareworker
docs/security-audit-2026-11-13.md).

## Stop conditions

- Any auth-delay (91AD) persistence on a card → stop touching that
  card (budget discipline; recovery playbook in AGENTS).
- bench_inventory FAIL beyond the known disk one → resolve before RF.
- The pn7160-nucula lane's WIP on small must not be touched — worktree
  isolation only.
