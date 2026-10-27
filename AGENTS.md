# AGENTS.md — bolty-rs Project Knowledge Base

## STM32 (bolty-stm32) bench notes

First hardware bring-up (2026-10-19, F469I-DISCO via place `stm32-ccid`)
PASSED at skeleton scope — full session entry with the four build-config
rules that silently kill RTT (`strip`, `-Tdefmt.x`, compile-time
`DEFMT_LOG` filtering, `debug = 2` for defmt string storage), the
st-flash flash/verify commands, and the open probe-rs-vs-WFI finding:
**docs/stm32-bringup-2026-10-19.md**. Read it before any STM32 bench work.

## Hardware Testing (shared Amperstrand bench, 2026-10-09)

Bolt-card hardware testing uses the SAME labgrid-coordinated bench as
ccid-firmware-rs (ai-legion). Before any bench work with an NFC device:

1. Check bench health: `python3 /root/src/ccid-firmware-rs/tests/hardware/labgrid/bench_inventory.py`
2. Acquire the device's labgrid place before touching hardware
   (`labgrid-client -p <place> acquire`; places: `stm32-ccid`, `nucula-c3`,
   `m5stick`, `ref-acr1252`, `ref-cardman`)
3. Reader selection in tests: by USB serial / stable identity, never
   enumeration order.
4. Queue, don't race: `labgrid-client reserve --wait name=<place>` (+
   `--priority` for CI lanes), then `-p + lock`. Cross-project
   practices — coordinator address, exporter state, exclusion domains,
   trusted-network security — live in **conwrt-bench
   `docs/labgrid-coordination.md`** (single source of truth).
5. **Bench-reader NVM config is shared state (B33)** — the ACR1252 has
   TWO EEPROM registers that can silently kill card detection across
   replugs AND host moves (auto-polling + PICC operating param). Never
   leave them non-default; for temporary RF quiet use a transparent
   session (`FF C2 … 81`/`82`, API §5.2.1) which auto-restores. The
   `tools/hil` check-in probe audits both registers and heals them to
   defaults (`BOLTY_ACR_CFG_HEAL=0` to skip); manual restore:
   `python3 -m hil.acr_probe --restore` from tools/hil/. If a reader
   "sees no cards" while USB/firmware answer fine, read
   `FF 00 50 00 00` FIRST — a `90 3F`-style response means polling is
   off, not that the reader died (lesson B33, issue #214).

The M5Stack Atom + MFRC522 rig (bolty's primary target) is the `m5stick`
place; the nucula (PN7160) is available for differential NFC work.

## Spec Conformance (greatspectations)

Spec-relevant code carries verbatim boltcard-spec quotes as `//` comments with
markers `BOLT_SPEC:` / `BOLT_DET:` / `BOLT_PRIV:` (sources: boltcard/boltcard
`docs/SPEC.md`, `docs/DETERMINISTIC.md`, `docs/CARD_PRIVACY.md`). CI
(`spec-quote-drift.yml`) verifies every quote against a fresh spec clone on
push/PR + weekly cron. Run locally:

```bash
git clone --depth=1 https://github.com/boltcard/boltcard.git spec
python -m greatspectations check --config specquotes.toml \
  --comment-start '// ' --comment-continue '//' -k \
  $(git ls-files 'crates/bolty-core/src/*.rs' 'crates/bolty-ntag/src/*.rs' 'apps/bolty-cli/src/*.rs')
```

Rules learned the hard way (2026-08-25):
- Consecutive `//` comment lines join into ONE multi-line quote matched
  against contiguous spec text — separate quotes from prose with a blank line.
- Quotes must be verbatim: backticks, markdown links, trailing table pipes,
  even upstream typos ("specfying" is pinned deliberately).
- Directories are not accepted as file args — enumerate `.rs` files.
- Cross-implementation audits use plain `Audited <date> against <impl>` comments
  at the audited site (e.g. `picc_verify_c` vs Go boltcard `check_cmac`).
- NXP PDF-layer facts (datasheet, AN12196) have no canonical text source and
  are NOT quote-covered — that layer is guarded by byte-exact fixture vectors.

## Lab & Service Topology (documented 2026-08-27)

**RIG STATE CHANGE (2026-09-09 audit — SUPERSEDED, see below):** the M5Stick
ran **nucula** firmware (Cashu wallet) from ~2026-09-03; that role-switch
warning is historical.

**CURRENT m5stick STATE (2026-10-27, RESOLVED):** the stick runs **bolty bench
firmware at main + the `grove` command** (elf `91db62bb…`). The MFRC522 that
died at the Oct 26 04:55 stick-local brownout (see below) was **LATCHED, not
dead** — no ESP32 reset drops the AXP-managed Grove 5 V rail, so it never
power-cycled until the new fw `grove off`→`grove on` (AXP192 EXTEN) console
command did it remotely: reader back at `i2c_scan=0x28`, `nfc=ok`. This
failure class is now self-service. The stick took TWO ~4:5x AM stick-local
brownouts (Oct 26 + Oct 27) with zero kernel USB events — recurring pattern,
watch it. Full story + recovery runbook: docs/hil-incident-2026-10-26-222.md.


Two lab machines + Cloudflare edge. **Use mDNS names, not IPs** (DHCP drift:
this box was .218 in early docs, .221 now).

| Host | What runs there | Why |
|---|---|---|
| `ai-legion-small` (Lenovo, GNOME, WiFi, mDNS `ai-legion-small.local`) | bolty-rs dev + esp toolchain; `proxy-healthcheck` timer; parallel AI-agent sessions; rotating Docker LN/regtest lab (CLN nodes, swapserver experiments); **ACR1252 bench reader** (place `ref-acr1252-small`, the ACR lane) | the working machine |
| `ai-legion` (RTX 3080 box, `192.168.13.208`, mDNS `ai-legion.local`, SSH-only from outside) | archival Bitcoin full node (coldcardforensic project); labgrid coordinator (:20408); **m5stick + nucula-c3 HIL seats RE-HOMED HERE ~2026-10-25** (both `bolty-console*` services + `/run/bolty/*.sock` live here now — the ai-legion-small-rig exporter is dead; incident write-up: docs/hil-incident-2026-10-26-222.md) | heavy always-on-ish compute |
| Cloudflare edge | `boltcardpoc.psbt.me` = edge-native HIL tap worker (Worker-style headers; routes deterministic-key anonymous taps — B12); DNS/proxying for `*.psbt.me` | edge = immune to lab-host outages |
| **UNKNOWN — the gap** | `proxy.psbt.me` origin: Go boltcard + PostgreSQL + LND + `cloudflared` tunnel. DOWN since ≤2026-08-27 18:25 (530/err 1033, tunnel disconnected). Not on ai-legion-small (verified), not listening on ai-legion (verified) | undocumented host = bus factor 1 |

Diagnosis runbook for proxy outages:
1. `journalctl -t bolty-proxy-health -f` (ai-legion-small) — current state
2. Cloudflare Zero Trust → Tunnels — connector host + last-seen (identifies
   the origin machine and when it dropped)
3. On the origin: `systemctl status cloudflared` / `docker ps` — restart
   policy must be `always`
4. While there: confirm internal API (:9001, unauthenticated
   `createboltcard`/`wipeboltcard`) is NOT reachable from the internet
5. boltcardpoc (edge) is independent — HIL taps stay green during proxy
   outages by design

### HIL rig quick facts (2026-09-02; full detail: docs/lessons-learned.md B24-B26)

Next scheduled bench session: **docs/hil-runbook-2026-10-13.md** (phased —
ACR-only work is safe while the stick runs nucula; stick reflash phases are
owner-gated). Includes the bench-evidence task for the 2026-10-12 MFRC522
dwell/activation-ladder port (`tests/test_activation_ladder.py`) and the
BLE Phase-3 gate (the bt module dry-compiles on IDF v5.5.5 — lesson B31).

- Cross-project bench sharing via the shared labgrid coordinator (places:
  bolty-rig, microfips-bench, gm65-qr-loopback, nucula-rig) — topology,
  locking order, and the gm65-scanner lessons learned are documented in
  docs/labgrid-bench-sharing.md.
- Entry points: `make test-hil` (fast, ACR only) · `make difftest` /
  `make difftest-quick` (66/66 in ~3:40 / 46/46 in ~2s) · `make test-hil-lg`
  (full labgrid plugin path) · `make report` (Allure) · `make status`
- labgrid: coordinator lives at `192.168.13.208:20408` (moved off .221
  in the 2026-09-26 consolidation — conwrt-bench
  `docs/labgrid-coordination.md` is the SINGLE SOURCE OF TRUTH for
  topology, exporter state, queueing (`labgrid-client reserve --wait`,
  not poll-acquire), one-device-one-exclusion-domain, and the
  trusted-network security model; read it before bench work).
  Coordinator restarts wipe places → `make labgrid-place`. Exporter
  YAML: class keys must be in labgrid's exports[] map (`USBSerialPort`,
  not the client-visible name); comments must be `##` (`# ` lines are
  Jinja statements). Traps in B25.
- Rig exclusivity: coordinator place acquisition first, flock fallback when
  the coordinator is down (conftest rig_lock / sessionstart — B26).
- Cards: registry `tools/hil/cards.toml` is the contract (burn tests are
  parametrized per burn-allowed card; non-coupled auto-skip). Placement is
  volatile — verify what is coupled before mutating (2026-10-19 evening:
  `043365FA967380` — recovered-static-key, see the recovery section — on
  the ACR antenna; one unidentified boltcard on the nucula PN7160 antenna;
  earlier the Samsung S20 HCE rig was stacked on the ACR for the
  boltcard-rig vertical round-trip, and `04C474FA967380` / `04455FFA967380`
  are off-reader at unknown positions).
- ACR1252 health (2026-10-19): the 2026-10-17 firmware-wedge (#101) did
  NOT reproduce — full Phase-1 cycle + 3/3 S20-HCE round-trips through
  it (session log in docs/hil-runbook-2026-10-13.md). Reader selection in
  bolty-cli skips virtual vpcd readers and honors `BOLTY_READER` (#121) /
  `--reader` (loud error on an unmatched pin) / `bolty-cli readers` (#134).
- ACR1252 health (2026-10-25): FULLY RECOVERED on ai-legion-small after
  the 2026-10-22→24 "death" was root-caused as an NVM auto-poll-off
  write by a sibling session (B33) — NOT hardware damage, NOT the B32
  wedges. USB/CCID/firmware were healthy the whole time; restore =
  `FF 00 51 FF 00` + `E0 00 00 23 01 8B`, verified by 5/5 NTAG424 UID
  reads (`04c474fa967380` on the antenna). Config now audited + healed
  automatically at every HIL check-in (conftest, B33).

## Card Recovery: UID 043365FA967380 — RESOLVED 2026-10-19

### Status: RECOVERED — factory-blank, back in burn service (registry alias `recovered-static-key`)

The stuck-key card was recovered live on 2026-10-19 (PR #129), confirming
the original root cause: burned by the **M5StickC Plus firmware with static
test keys** (K0 = `0x11`×16). Recovery sequence, now the playbook for this
class:

1. `bolty-cli try-key --key <candidate> --attempts 150` — deep-delay ladder
   (this card's 91AD delay spent at attempt ~21-25; the historical "zeros →
   91AD" table entry was a MASKED test — delay blocks key evaluation, so
   91AD ≠ wrong key; only 91AE after delay-spend disproves a candidate).
2. `bolty-cli wipe --raw-keys 1111..+2222..+3333..+4444..+5555.. \
   --confirm-uid <uid> --skip-preverify` — static-keyset wipe; the DET
   pre-verify gate can't parse a half-wiped NDEF, and a try-key-PROVEN K0
   provides the wrong-key protection it exists for.
3. Post-wipe `try-key --key 0000...0` — ACCEPTED = genuinely factory-blank.

The historical recovery notes below are retained for the counter mechanics
(budget discipline still applies: TotFailCtr 1000 = permanent key lock).

### What We Know

- **Chip**: NTAG424 DNA (HW vendor=04, type=04, v=30.00 | SW v=01.02)
- **Manufactured**: Calendar Week 19, 2021 (batch 3475920457 — corrected 2026-10-20 from a live `ver` read; the earlier "CW25 / CF2E56 / wafer 495019" row belonged to another card, evidence /tmp H1 lane log `08-ver-043365.log`)
- **NDEF**: 256 bytes, contains URL template `boltcardpoc.psbt.me/?p=...&c=...`
  with all-zero placeholders (SDM not dynamically replacing)
- **SDM Config**: Active, standard MAC configuration
  (`MacWindow { input: Offset(127), mac: Offset(127) }` — input==mac)
- **Card State**: HALF-WIPED (SDM configured, NDEF invalid)
- **GetKeySettings**: `004000E0000100C1FF125C00007F00007F0000`
  (byte offset 5 = 0x01, suggesting K0 at version 1)
- **File Access**: read=Free, write=Key0, read_write=Key0, change=Key0

### What We've Tried

| Key Candidate | Result | Notes |
|---|---|---|
| Factory K0 (all zeros) | `91AD` AuthDelay | Card not at factory defaults |
| Derived K0 v1 (`40577668...`) | `91AE` AuthFailed | Card accepted challenge, rejected response |
| Derived K0 v0, v2, v3 | `91AD` AuthDelay | Accumulated delay from prior failures |

**Derived K0 v1** = `4057766867304a7610bbf7c31ed93ce1`
(computed from issuer key `00000000000000000000000000000001`, UID `043365FA967380`, version 1)

### Root Cause Analysis

**The card was most likely burned by the M5StickC Plus firmware using STATIC test
keys, NOT by bolty-cli with derived keys.**

Evidence:
1. **M5StickC uses static keys** — the `keys` command stages literal hex keys
   (e.g., `K0=11111111111111111111111111111111`), not derived keys
2. **Derived K0 v1 is wrong** — card returned `91AE` (wrong key), not `91AD` (delay).
   This proves the key on the card is genuinely different from derived K0 v1.
3. **ChangeKey for K0 writes directly** — master key change doesn't use old_key
   (no XOR), so a bolty-cli burn would have written derived K0 v1 correctly.
   Post-burn re-auth verifies it. If burn succeeded, K0 MUST be derived K0 v1.
4. **Background polling causes auth delay** — the M5StickC firmware's polling loop
   spams auth attempts every 500ms. After wipe, it tries STALE keys against the
   now-factory card, causing ~2 failures/second. After 50 consecutive failures
   (~25 seconds), the card enters auth delay (`91AD`).

**Sequence of events (most likely):**
1. Card was placed on M5StickC reader
2. Static test keys were staged and URL was set to `boltcardpoc.psbt.me`
3. `burn` command wrote static keys + SDM config to card
4. Something triggered repeated auth failures (wipe attempt, polling, card swap)
5. SeqFailCtr exceeded 50 → card entered auth delay
6. bolty-cli wipe/burn tried derived keys → wrong key → more failures

### NTAG424 Auth Delay Mechanism (AN12196 §7.4)

Three per-key counters track authentication failures:

| Counter | Size | Trigger | Reset |
|---|---|---|---|
| **SeqFailCtr** | 1 byte | 50 consecutive failures → delay starts. Gradually increases to 255. | Successful auth OR ChangeKey |
| **TotFailCtr** | 2 bytes | 1000 total failures → **key permanently locked** | ChangeKey only |
| **SpentTimeCtr** | 2 bytes | Tracks delayed response time | ChangeKey only |

- After SeqFailCtr >= 50: card returns `91AD` immediately (blocks auth processing)
- After TotFailCtr >= 1000: **key permanently disabled** (card bricked for that key)
- Counters are reset by `Cmd.ChangeKey` (requires successful K0 auth first)
- SeqFailCtr is non-volatile — "keep trying" (rapid AuthFirst in same connection) clears delay

### Recovery Plan (When Card Is Back On Reader)

**Step 1 — Power cycle the card:**
Remove card from reader, wait 2 seconds, place back. **This does NOT clear
SeqFailCtr** (non-volatile). Instead, use "keep trying" — send AuthFirst
repeatedly within the same PCSC connection (2-5 attempts clears the delay).
The bolty-cli `try-key` command does this automatically (default 20 rapid
retries; `--attempts` raises the ladder for deep-delay cards).

**Step 2 — Try static test key FIRST:**
```bash
# On Ubuntu, try the M5StickC static test key
./target/debug/bolty-cli wipe --issuer-key 00000000000000000000000000000001 --version 1
# If this fails with 91AE, the card doesn't have derived keys — try static key
```

If bolty-cli doesn't support raw key authentication, use the M5StickC:
```
keys 11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444 55555555555555555555555555555555
wipe
```

**Step 3 — If static key works:**
Card is now factory blank. Re-burn with bolty-cli using derived keys.

**Step 4 — If static key fails, try other candidates:**
- Derived K0 v0: `68c3abc1d72e8a4f49cf294a9a2813c3`
- Derived K0 v2, v3 (computed with `--version 2` or `--version 3`)
- Card key (v1): `b86751eaa2fc214bd3b746caf7db5e51`
- K1 (issuer-derived): `55da174c9608993dc27bb3f30a4a7314`

**Step 5 — If all fail:**
TotFailCtr may have reached 1000 (permanent lock). Card is bricked for key
management but can still be read (read=Free). Use as read-only test artifact.

### How to Prevent This

1. **Fix M5StickC polling bug** — background loop must STOP attempting auth after
   first failure. Currently spams every 500ms, causing SeqFailCtr to skyrocket.
2. **Add auth-delay awareness to M5StickC** — detect `91AD` and suspend polling.
3. **Improve bolty-cli auth delay handling** — current 5s/15s/30s backoff with
   circuit breaker (10 failure limit). Implemented in commit `6d08cbb`.
4. **Never leave provisioned cards on M5StickC reader** when firmware is polling.
5. **Add `try-key` command to bolty-cli** — test specific raw key without full wipe.
6. **Track which tool burned each card** — log UID + tool + key type in audit log.

### Auth Delay Recovery (Empirically Verified)

SeqFailCtr is **non-volatile (EEPROM)** — it does NOT reset on power loss,
RF field removal, or reader reboot. Power cycling does NOT clear it.

**Recovery: "Keep trying" (per NT4H2421Gx datasheet)**

The NTAG424 product data sheet states for AUTHENTICATION_DELAY (0xAD):
*"Currently not allowed to authenticate. Keep trying until full delay is spent."*

This means: send AuthFirst **repeatedly within the same PCSC connection**.
Each attempt "spends" part of the delay. Empirically verified: 2-5 rapid
AuthFirst commands clears the delay.

**CRITICAL: Each new PCSC connection resets the delay state.** Creating a new
connection per retry does NOT work. The retries must happen within a single
transport session.

**What does NOT work:**
- New PCSC connection (warm reset) — resets delay state
- `systemctl restart pcscd` — reader keeps antenna on
- `SCARD_UNPOWER_CARD` — does not cut RF on ACS ACR1252
- USB driver unbind/bind — device stays in sysfs, VBUS stays powered
- USB root hub power cycle — reader reboots but SeqFailCtr persists
- Physical card removal — does NOT clear SeqFailCtr (non-volatile)
- Waiting (any duration) — delay is NOT time-based

### Tools for Recovery

```bash
# On Ubuntu (192.168.13.218), using debug binary:
cd /home/ubuntu/src/bolty-rs
./target/debug/bolty-cli diagnose --issuer-key 00000000000000000000000000000001

# Compute derived keys without touching card:
./target/debug/bolty-cli derive-keys --issuer-key 00000000000000000000000000000001 --uid 043365FA967380 --version 1 --verbose

# M5StickC (serial port):
# Port: /dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0
# Commands: keys <k0> <k1> <k2> <k3> <k4>, burn, wipe, inspect, uid
```

### References

- NXP AN12196 §7.4: FailedAuthentications Counter feature (auth delay mechanism)
- NXP NTAG424 DNA Product Data Sheet Rev. 3.0 §10.6.1: ChangeKey command
- NXP Community: Change Keys and "lock" NTAG DNA 424
- AndroidCrypto: A comprehensive overview of all keys for the NTAG424 NFC chip

## KNOWN-GOOD NUCULA C3 — board-nucula firmware (2026-10-23, re-verified 2026-10-25 @ main c562a1d; re-flashed 2026-10-27 @ main 630eb62)

The nucula C3 runs bolty `board-nucula` firmware at main (PRs #185/#186/#193;
re-flashed + re-verified at `c562a1d` on 2026-10-25, see the console-contract
bullet), fully functional with a coupled card. This is the reference state
for the #115 frontend and any future nucula work:

**STATE 2026-10-27 (issue #222 close-out):** the board was found wedged
(console garbage → deterministic app_main hang after an overnight fw panic;
coredump preserved in `/root/bench/c3-incident-20261027/` on ai-legion) and
was RECOVERED by reflashing main @ `630eb62` (console verified: status/uid/
poll OK, `nfc=ok`). Full root cause — including the bolty-console restart
loop that reset the board every ~6 s (pyserial DTR reopen pulse =
USB_UART_CHIP_RESET; now fixed: same-fd stall retry + StartLimit on the
c3 unit) — in **docs/hil-incident-2026-10-26-222.md**. The seat now lives
on ai-legion (see the topology table), NOT ai-legion-small. A random-ID
emitter (S20-class) is coupled to the antenna — decouple before console
work (junk-spray lesson below).

- **Console**: fully interactive over `/dev/ttyACM0` at 115200 (commands:
  help/status/uid/poll/inspect/ver/wifi). Requires the `UsbSerialDriver`
  peripheral claim at boot (#186) — without it, the ROM owns USB_SERIAL_JTAG
  and mirrors TX only (stdin never arms, host writes stall at USB level).
- **Console contract (#204/#205, hardware-verified 2026-10-25)**: overlong
  lines fail exactly once with `command too long` and the trailing command
  does NOT execute (513-pad+`poll` proven on-device); a 512-byte line parses
  (unknown-command echo, truncated at the 384-byte `ok_fmt` cap — capacity
  behavior, not a parser limit); the first line after an overlong one
  answers normally. Transport caveat: the USB_SERIAL_JTAG RX buffer is
  1024 bytes — a host that writes MORE than ~1KB back-to-back (e.g. a long
  pad line immediately followed by a command) loses the burst TAIL; settle
  briefly between a >1KB write and the next command.
- **Console daemon**: `bolty-console-c3.service` (systemd, enabled) owns
  `/dev/ttyACM0` via `/run/bolty/console-c3.sock` (journal:
  `/root/.bolty/console-c3.log`). FLASHING REQUIRES
  `systemctl stop bolty-console-c3` first — SIGTERM-ing the python process
  alone does nothing (systemd respawns it mid-flash and espflash dies with
  "Communication error"; rediscovered 2026-10-25).
- **Reader**: PN7160 up with full NCI ladder logged at boot; `[OK] PN7160
  reader up (NCI-DEP power-on)` appears ~500ms after reset.
- **Card ops**: `status → nfc=ok session=active uid=<UID>`, `poll → [OK] card
  up`, `uid → [OK] uid=<UID>`, `inspect → uid=<UID> ndef_bytes=N sdm=<bool>` —
  all proven against `04c474fa967380` (2026-10-23), run twice consecutively
  without leak. 2026-10-25 note: the antenna then held a RANDOM-ID tag
  (`08:4C:13:19`, 88-byte NDEF, sdm=false — not the known NTAG; possibly the
  S20 lying on the antenna). A random-ID/junk coupling also sprays
  `pn7160_nci read_frame` warnings at ~5 Hz, which floods the console
  daemon's 400-line ring and breaks its 1.0s quiescence detection (socket
  replies stall to the 40s cap). Keep non-NTAG RF emitters off the C3
  antenna during console work — EXCEPT in relay mode (next bullet), where
  the S20 IS the intended antenna occupant.
- **Virtual NTAG424 over the S20 (2026-10-25, bench-proven)**: the S20's
  `dev.boltcard.hce` app has a relay mode (tap its screen to toggle) that
  forwards every APDU to a bridge on ai-legion-small (`boltcard-relay-bridge`
  systemd unit, /root/bench/relay_bridge.py, pcsc→ACR1252), giving the C3
  virtual access to the REAL NTAG424 coupled over there — no hardware moves.
  Proven with `poll`/`uid`/`inspect`: live SDM NDEF read through two wireless
  hops, p= counter ticking between reads, 2–17 ms/APDU. RF-level UID is the
  phone's random ID (unrelayable); the console `sdm=` heuristic shows false
  even while mirroring is live on the wire. Full architecture + ops in
  /root/src/boltcard-hce/AGENTS.md (relay mode section).
- **Heap discipline**: all console output MUST be heapless (`String<N>` via
  `write!()` — NEVER `format!()` on this target; the C3 has ~143KB heap
  shared by WiFi+PN7160+console; `format!()` exhausted it and crashed the
  firmware — coredump-decoded, PR #193).
- **sdkconfig**: `sdkconfig.defaults.nucula` (USB_SERIAL_JTAG primary console,
  `ESP_MAIN_TASK_STACK_SIZE=32768` — default stack overflows at `app_main`).
- **Crash log**: `crashlog` command reports boot count + last crash; clean
  (no crashes since #193's fix).
- **To restore CCID firmware**: re-flash via ccid-firmware-rs `build.sh c3-ccid`
  (the pcscd reader `Nucula CCID via broker` is absent while bolty runs).

## KNOWN-GOOD DISPLAY STATE — M5StickC Plus (2026-10-23, owner-verified)

The stick's ST7789 display works on the current bench boot — physically
confirmed by the owner while the bolty console bench ran. This is a
cross-project reference state: **ccid-firmware-rs and the nucula/cashu
work target the same M5StickC Plus hardware** and can study/port this
exact recipe instead of rediscovering the AXP192 sequencing.

Verified state (console `hwinfo`: `display_init=ok`, boot log "Display
init: starting AXP192 I2C1 on GPIO21/GPIO22..."; firmware flavor
"archive/test/73-graduation-wave", display stack unchanged in main):

- **Power sequencing FIRST** (`apps/bolty-esp32/src/display.rs`
  `init_axp192` + `axp192_map.rs`): AXP192 on **I2C1, GPIO21=SDA,
  GPIO22=SCL @ 100 kHz** — LDO2/LDO3 = 3.0 V (0xCC; backlight + panel),
  power-out ctl (0x12) OR 0x4D (DCDC1+LDO2+LDO3+EXTEN) with read-back
  verify, ADC all-on, charge 4.2 V/100 mA, PEK key timing, GPIO0 LDO
  3.3 V, Grove 5 V boost.
- **Panel driver**: ST7789 via the `mipidsi` crate (ColorInversion),
  SPI2 with the M5StickC Plus pin set (13/15/5/23/18/27 — DC/CS/SCK/
  MOSI/BL/RST per `firmware.rs` display::init call site).
- **Bus isolation**: display lives on I2C1 + SPI2; the MFRC522 reader
  lives on I2C0 (GPIO32/33, also 0x28). Same boot survived a transient
  I2C0 "SDA stuck LOW" fault (software bus-recovery clocked through;
  reader init still succeeded) with the display's I2C1 unaffected —
  the two-bus split is why the display state is robust.

## Hardware Test Results (2026-06-15)

### KNOWN GOOD STATE (2026-08-28 — current)

Firmware: HEAD `51e8a50` (keyver fix), features `board-m5stick,wifi,rest`,
sha256 `06fd7912…` (workspace target; restamp on rebuild). Extensive battery
run DURING the proxy.psbt.me outage (which blocked nothing below):

- **Outage immunity proven**: full burn cycle ALL PASS with live worker tap
  HTTP 200 while proxy.psbt.me returned 530 simultaneously — HIL depends on
  the edge worker (boltcardpoc), not the proxy.
- **REST key lifecycle, both directions**: provisioned card + no staged keys →
  `/api/inspect` AND `/api/keyver` honestly return `authentication failed`
  (closed the always-200 caveat); correct keys staged via `POST /api/keys` →
  ok + live SDM confirm (`sdm=ok keys_confirmed=true`, ctr=155).
- **keyver was a silent no-op** (reported success without touching the card)
  — found by the negative test, fixed (`51e8a50`), hardware-verified.
- **Percard mode ALL PASS** (`burn_cycle.py --percard`, April k0/k1/k2 +
  synthetic k3/k4): the edge worker routes per-card taps via the K1
  fallback; the psbt.me global decrypt key is shared with the worker.
- **OTA NEGATIVE attack**: wrong-key Ed25519 signature → full 1.27 MB
  download → `signature verification FAILED` → update Dropped (not
  committed) → device unaffected on factory slot. OTA trust chain holds.
- **Endurance**: 6 full burn→tap→wipe lifecycles in one day (2× standard,
  1× skip-wipe, 1× percard, 2× endurance), zero failures, zero port wedges.
- **hwtest ×2**: non-button hardware ALL OK (i2c 0x28, nfc, display,
  battery 4100 mV USB); button software subsystem VERIFIED (mode get/set,
  legacy/simple switching, NVS persistence across reboot); interactive
  mechanism works (honest timeout FAILs, clean END). Physical button
  presses + card-removal still need a human at the rig.

Device state at stamping: standard layout (factory @ 0x10000), keyver-fix
build, card `04C474FA967380` blank lab stock, button mode simple, console
daemon up, REST unprovisioned this boot (runtime creds).

Still not hardware-tested: BLE (blocked upstream), physical button presses
(user action — run `hwtest` and press front then side button on prompt).

### KNOWN GOOD STATE (2026-08-27)

Firmware: HEAD `5011a97` — all session work committed (the earlier partial
stamp referenced uncommitted rest.rs; that landed as `0706cf2`). Verified:

- **Full burn cycle ALL PASS, twice** (`tools/hil/burn_cycle.py`): burn
  (deterministic issuer) → `inspect provisioned` → `picc sdm=ok uid_match=true`
  → **live worker tap HTTP 200** (boltcardpoc.psbt.me) → wipe → `state=blank`.
  Hardware-proves the `cmac` crate swap on the real derivation path; the
  final restored binary got its own second full cycle.
- **OTA update flow VERIFIED end-to-end** (first time on hardware):
  `board-m5stick,wifi,rest,ota` build + flash-time `--partition-table
  partitions.csv`, `provision-ota-key`, HTTP-served signed image → 1,266,864
  bytes streamed over WiFi → SHA-256 → **Ed25519 signature VERIFIED —
  committed** → reboot → booted **ota_0 @ 0x200000** (boot-log proof, otadata
  persistence included). Device afterwards restored to the standard default
  partition table.
- **REST keyver/inspect report operation results** (previously always-200;
  commit `0706cf2`).
- REST full matrix re-verified: TLS :81, 401/200 auth, JSON escaping,
  400/429 paths.
- Spec-quote CI: 22 greatspectations quotes green; `esp32-check.yml` is a
  REAL xtensa build (first GitHub-runner run still pending at stamping).
- Host suite 20/20; firmware builds clean (ldproxy stderr warning is benign).

**BLE: blocked upstream, not a local bug** (commit `5011a97`). Two stacked
causes: (1) `[package.metadata.esp-idf-sys.sdkconfig]` BT table silently
ignored by esp-idf-sys 0.37.2 (0 CONFIG_BT lines in gen-sdkconfig.defaults) —
removed; (2) the esp-idf-svc fork's bt module needs ESP-IDF ≥5.3 symbols
(`esp_ble_conn_params_t`, `esp_ble_gatt_creat_conn_params_t`) absent from the
pinned v5.2.3. WARNING: enabling Bluedroid in sdkconfig.defaults compiles the
broken bt module for EVERY build config — wifi/rest/ota all stop compiling.
Unblock = esp-idf-svc 0.53.0 + matching esp-idf-sys/hal bump; BT block is a
commented reference in sdkconfig.defaults; ble config dropped from
esp32-check.yml until then.

Device state at stamping: **standard layout restored** (default partition
table, factory @ 0x10000), final build flashed and burn-cycle-verified,
console daemon running, card `04C474FA967380` returned to blank lab stock.

Artifacts:
- Final verified binary: `~/fw-backup/bolty-esp32-knowngood-20260827-final.bin`
  (sha256 `c1dc3751…243e2`, features `board-m5stick,wifi,rest`)
- Same-day earlier binary: `~/fw-backup/bolty-esp32-knowngood-restfix-20260827.bin`
  (`4a2fae08…`; differs only by embedded build time + dead-metadata removal)
- OTA test materials: `~/fw-backup/bolty-esp32-ota-image-20260827.bin` +
  `ota_pub.hex` / `ota_sig.hex` (Ed25519 over SHA-256 of the image)

Still not hardware-tested: BLE (blocked upstream, see above), physical buttons.

### KNOWN GOOD STATE (2026-08-24)

Firmware `891d7f6` + working-tree fixes (partition sdkconfig removal, 4 REST/job
compile fixes, display battery-poll redraw guard). Verified on M5StickC Plus:

- Boot: clean, display ok (ST7789 via AXP192), MFRC522 @ I2C 0x28, no crashes
- Card `04C474FA967380` (externally provisioned by psbt.me proxy — NO known K0,
  do NOT wipe/burn; use only for read tests): uid/status/diagnose/picc all OK,
  SDM MAC regenerates per read (live counters, crypto path healthy)
- Serial console: ver/status/uid/button-mode/derivekeys/crashlog/inspect/picc/diagnose
- WiFi/REST VERIFIED (2026-08-24): `wifi <ssid> <pass>` → connect; REST is
  **TLS-only** — needs `provision-cert` first (on-device RSA-2048 self-signed,
  stored in NVS; without it `wifi` prints `rest start failed: ESP_ERR_INVALID_STATE`),
  then reconnect WiFi. Server: HTTPS on :443→no, **https_port = REST_PORT+1 = 81**
  (plain :80 refuses). Verified: bearer token auth (401 no/wrong token),
  GET /api/status|uid|diagnose|inspect, POST /api/job → 201 + GET /api/job →
  completed (wipe→`wipe_refused` with no keys staged, burn→`missing lnurl`),
  400 invalid/missing command, 429 on rapid writes (5s cooldown). mDNS
  advertise reports active (host has no resolver to confirm).
- Host test suite: 20/20 pass (`cargo test --workspace --exclude bolty-esp32`)
- NOT yet hardware-tested: BLE (opt-in feature; build with
  `--features 'board-m5stick,wifi,rest,ble'`), OTA (needs custom partition
  table flashed), physical buttons. (burn→inspect→wipe cycle: DONE
  2026-08-25, see the newer KNOWN GOOD section above)

Artifacts:
- Known-good binary: `~/fw-backup/bolty-esp32-knowngood-891d7f6-fixes.bin`
  (sha256 `09e04aa0…a79a4`, ELF 1.17MB, features `board-m5stick,wifi,rest`)
- Pre-session full-chip dumps (ccb3c74-dirty, working display):
  `~/fw-backup/bolty-dump{1,2}.bin` — restore with
  `esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 115200 write_flash 0x0 dump.bin`

Auth-attempt budget note: the test card has ~12 of 50 SeqFailCtr failures spent
(2026-08-24 key ladder). Unauthenticated commands (picc/diagnose/status) are free;
authenticating with wrong keys consumes budget — avoid.

### KNOWN GOOD STATE (2026-08-25)

Firmware: bolty-esp32 main @ `beaf99a` (heartbeat carries `nfc=ok|DOWN`).
Stick on the bolty serial console, served by the `bolty-console` daemon
(tools/hil/ — port opened once per boot, unix socket at
/run/bolty/console.sock; udev rule ignores ModemManager; see
docs/lessons-learned.md B11). Zero USB wedges across a full session since.

**Full burn→inspect→live-tap→wipe→blank cycle COMPLETED on card
04C474FA967380** (the 2026-08-24 gap below is closed):
- Deterministic burn (public issuer `0000…0001`, v1,
  `https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}`) → `burn complete`
- `picc` → `sdm=ok uid_match=true`
- Live worker tap → **HTTP 200 withdrawRequest** (callback + k1=c convention)
- `wipe` → `state=blank`; re-burn/wipe cycles repeatable
- Run it: `python3 tools/hil/burn_cycle.py` (B12: deterministic keys are the
  anonymous-tap path; percard `--keys` burns are valid but not routable by an
  anonymous first tap)
- Card state after the test run: **blank** (returned to lab stock)

ccid-firmware-rs (same stick, when used as a CCID reader): board-m5stick
feature, sdkconfig gate via flash_and_test.sh — switching roles means
reflashing; bolty is the default role.

### PCSC ACS ACR1252 — FULLY WORKING
Full cycle tested: diagnose(blank) → burn → diagnose(mac=true) → wipe → diagnose(blank)
- Card UID: `040c60fa967380`
- SDM MAC verification: ✅ `mac=true` with standard `[[{mac}` URL template
- `standardize_url_template` fix working correctly

### M5StickC Plus (Hades2001) — FULLY WORKING
- Card UID: `040C60FA967380` (current)
- Serial port: `/dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0`
- Burn → inspect(provisioned) → wipe → inspect(blank): ✅
- WiFi: SSID "2", IP 192.168.13.236, REST API port 80, mDNS bolty.local ✅
- Polling bug: FIXED (commit 18a9b37 — no more auth spam)

### ESP32 Build Commands (Ubuntu 192.168.13.218)
```bash
# One-time setup:
cargo install espup espflash
# BOTH pins load-bearing (ccid-firmware-rs #150): the fork version floats to
# latest without -v, and ≥1.99.0.0 rust-src breaks -Z build-std on *-espidf
# (fchmodat/AT_FDCWD libc gap, rustix#1652). Crosstool pin: IDF v5.5.5's
# tool_version_check accepts esp-14.2.0_20260121 and rejects the 20241119
# build — always pin (CI does the same):
espup install -v 1.98.1.0 -c 14.2.0_20260121
# Verify xtensa std is present (interrupted espup installs lose it):
rustup +esp target list --installed   # must NOT be only x86_64-unknown-linux-gnu
# If missing: the build fails with E0463 "can't find crate for `core`".
# espup 0.17 ships host-std-only toolchains; std is built from source
# via -Zbuild-std (see apps/bolty-esp32/.cargo/config.toml).

# Canonical bench build (2026-10-12+): build.sh pins CARGO_WORKSPACE_DIR +
# a repo-local CARGO_TARGET_DIR (the shared global target dir once silently
# built v5.2.3 under a v5.5.5 manifest pin — lesson B30) and FAILS LOUDLY if
# the resolved ESP-IDF does not match the manifest pin:
cd apps/bolty-esp32
./build.sh m5stick                      # board-m5stick,wifi,rest,ota
./build.sh m5stick --flash /dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0
./build.sh m5stick-ble --sdkconfig sdkconfig.defaults.ble   # BLE experiment
# After an esp_idf_version bump: ./build.sh m5stick --clean-sys

# Raw cargo (what build.sh wraps) — MUST run from apps/bolty-esp32/ (the
# .cargo/config.toml there supplies --target xtensa-esp32-espidf + build-std
# + ESP_IDF_SYS_ROOT_CRATE; building from the workspace root silently
# produces a useless x86-64 host binary):
cd apps/bolty-esp32
export CARGO_WORKSPACE_DIR="$PWD/../.." CARGO_TARGET_DIR="$PWD/../../target"
. ~/export-esp.sh
cargo +esp build --release --features 'board-m5stick,wifi,rest'
# Output: target/xtensa-esp32-espidf/release/bolty-esp32
# Verify the IDF actually used (must end with the manifest tag):
python3 -c "import json,glob; print(json.load(open(glob.glob('../../target/xtensa-esp32-espidf/release/build/esp-idf-sys-*/out/esp-idf-build.json')[0]))['esp_idf_dir'])"

# Flash (espflash default 115200 baud — reliable on this FT232 link):
cd ../..
espflash flash --port /dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0 \
  target/xtensa-esp32-espidf/release/bolty-esp32
```

### Flash Link Reliability (empirical, 2026-08-24)
- `esptool read_flash` at 921600/460800: **fails** ("chip stopped responding" —
  known issue class with marginal USB-UART bridges; esptool issues #250/#967).
- 115200: 2× full 4MB reads 100% stable.
- Full-chip dump checksums differ between reads **by design**: the firmware
  writes boot-count/crash-log entries to NVS (0x9000–0xF000) on every boot and
  each esptool run hard-resets the chip. Verify backups by diffing regions:
  `cmp -l dump1 dump2` — differences must fall inside the NVS partition only.
- Verified backup of known-good firmware (2026-08-24, ccb3c74-dirty +
  working display): `~/fw-backup/bolty-dump{1,2}.bin` (sha256 differ only in
  NVS 0x9025–0x92fb).
- Custom partition tables: pass at flash time
  (`espflash flash --partition-table apps/bolty-esp32/partitions.csv`);
  `CONFIG_PARTITION_TABLE_CUSTOM` in sdkconfig.defaults breaks esp-idf-sys
  cargo builds (esp-rs/esp-idf-sys#395).

## Difftest Policy: MANUAL for now (2026-08-30)

Unattended runners are deliberately NOT set up. Run the differential
manually when needed:

    cd tools/hil/difftest && python3 e2e.py --phase apdu   # expect 66/66

The role-switch + restore is handled by the harness (restore-always).
`.github/workflows/nightly-difftest.yml` is a DORMANT template
(workflow_dispatch only) — re-enable its schedule trigger and register a
'lab'-labeled self-hosted runner only if the policy changes.


## Lessons Learned

See docs/lessons-learned.md — append-only engineering log: rig facts (M5Stick pins, MFRC522 at 0x28), ESP-IDF sdkconfig traps, NTAG424 card-safety refinements (911E vs 91AE), and the byte-exact crypto port method.


## External posting (owner directive 2026-09-06 — CHANNEL rule)

Agents never post on non-member repos — no `gh` writes (issues, PRs,
comments, reviews, gists), not even with per-text owner sign-off; the
owner does the copy-paste into GitHub themselves. Member orgs (verify:
`gh api user/orgs`; 2026-09-06: Amperstrand, OpenTollGate, net4sats,
FreedomTechFeed) keep the existing owner-gate flow. Read the target
repo CONTRIBUTING/AI policy before drafting anything upstream.
Canonical text: lightning-playground AGENTS.md (standing rule UPDATE
2026-09-06).
