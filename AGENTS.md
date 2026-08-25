# AGENTS.md — bolty-rs Project Knowledge Base

## Card Recovery: UID 043365FA967380

### Status: RECOVERABLE (use "keep trying" — rapid AuthFirst in same connection)

A test card with UID `043365FA967380` is stuck in an unknown key state. It cannot
be authenticated with derived keys. The most likely cause: the card was burned by
the **M5StickC Plus firmware with static test keys**, not by bolty-cli.

### What We Know

- **Chip**: NTAG424 DNA (HW vendor=04, type=04, v=30.00 | SW v=01.02)
- **Manufactured**: Calendar Week 25, 2021 (batch CF2E56, wafer 495019)
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
The bolty-cli `try-key` command does this automatically (up to 20 rapid retries).

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

## Hardware Test Results (2026-06-15)

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

### KNOWN GOOD STATE (2026-08-25 — current)

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
espup install
# Verify xtensa std is present (interrupted espup installs lose it):
rustup +esp target list --installed   # must NOT be only x86_64-unknown-linux-gnu
# If missing: the build fails with E0463 "can't find crate for `core`".
# espup 0.17 ships host-std-only toolchains; std is built from source
# via -Zbuild-std (see apps/bolty-esp32/.cargo/config.toml).

# Build firmware — MUST run from apps/bolty-esp32/ (the .cargo/config.toml
# there supplies --target xtensa-esp32-espidf + build-std; building from
# the workspace root silently produces a useless x86-64 host binary):
cd /home/ubuntu/src/bolty-rs/apps/bolty-esp32
. ~/export-esp.sh
cargo +esp build --release --features 'board-m5stick,wifi,rest'
# Output: /home/ubuntu/src/bolty-rs/target/xtensa-esp32-espidf/release/bolty-esp32

# Flash (espflash default 115200 baud — reliable on this FT232 link):
cd /home/ubuntu/src/bolty-rs
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

## Lessons Learned

See docs/lessons-learned.md — append-only engineering log: rig facts (M5Stick pins, MFRC522 at 0x28), ESP-IDF sdkconfig traps, NTAG424 card-safety refinements (911E vs 91AE), and the byte-exact crypto port method.

