# Lessons Learned — bolty-rs Engineering Log

Cumulative, append-only. One entry per lesson; link the evidence. Sibling of the
cross-project log at `~/src/LESSONS-LEARNED.md` (Mac); entries here are specific to
bolty-rs, its hardware, and its NTAG424 tooling.

---

## B1 — A stale LCD frame is not firmware state
**Date:** 2026-08-25 · **Found in:** card 04C474FA967380 wipe session (ai-legion-small)
**Class:** hardware debugging

After flashing new firmware over the M5Stick on ai-legion-small, the LCD kept
showing the *previous* firmware's last rendered frame ("nfc ok"). That frame was
rendered by bolty at its last boot — it says nothing about what code is running
now. It actively misdirected the diagnosis ("are you sure you flashed the right
device?").

**Rules:**
1. A display shows the last thing the *running-or-previous* app drew. After any
   reflash, treat screen content as stale until the new app demonstrably renders.
2. Identify running firmware from the serial port (boot banner, heartbeat
   fingerprint — see B3), never from the screen.

---

## B2 — The ai-legion-small reader rig is an M5Stick layout, not an Atom Matrix
**Date:** 2026-08-25 · **Found in:** same session
**Class:** hardware / board config

The M5Stack device on ai-legion-small (USB VID 0403:6001, "M5STACK Inc." FT232)
has a **screen** — it is an M5Stick-class board, Grove I2C on **SDA=GPIO32 /
SCL=GPIO33** (`board-m5stick` feature), with an MFRC522 at address **0x28**.
The `board-m5atom` layout (SDA=26/SCL=32) finds nothing on this rig.
`ccid-firmware-rs` defaulted to Atom pins and its MFRC522 init timed out until
the pins were switched to 32/33 — after which the reader came up immediately.

**Rules:**
1. Board identity is a per-rig fact — record it next to the rig, not in your
   head. This rig: M5Stick pins 32/33, MFRC522 @ 0x28, working `esp32-ccid`
   firmware flashed 2026-08-25.
2. "No I2C ACK" on a known-good wiring almost always means wrong pin mux for
   the actual board variant, not a dead chip. Check the variant before the
   soldering iron.

---

## B3 — Fingerprint unknown firmware by its heartbeat strings
**Date:** 2026-08-25 · **Found in:** same session
**Class:** ops / reverse engineering

The stick answered a CCID probe with a plain-text heartbeat
(`[HB] alive t=33011869ms`) instead of protocol bytes. Grepping the string
across `~/src` pinned it to `apps/bolty-esp32/src/firmware.rs` — the chip was
running the bolty tollgate firmware, not (as assumed) the CCID reader. Total
identification cost: one grep.

**Rules:**
1. When a serial device speaks non-protocol, capture the raw bytes and grep
   the workspace for the literal string before theorizing.
2. Heartbeats that don't identify their app waste this opportunity — see B5.

---

## B4 — ESP-IDF sdkconfig traps: renamed options and undiscovered defaults
**Date:** 2026-08-25 · **Found in:** ccid-firmware-rs builds (same rig, shared toolchain)
**Class:** firmware build

Two silent failures hit the same firmware within one session:

1. `CONFIG_MAIN_TASK_STACK_SIZE` was **renamed** `CONFIG_ESP_MAIN_TASK_STACK_SIZE`
   in ESP-IDF 5.x. The old name is silently ignored → main task runs at the
   3.5 KB default → `vApplicationStackOverflowHook` → abort → boot loop with a
   `|<-CORRUPTED` backtrace. Symbolize the backtrace (`xtensa-esp32-elf-addr2line`)
   before touching code — the corrupted frames hide the real culprit.
2. `sdkconfig.defaults` files are **not** auto-discovered by embuild/cargo
   builds. They only apply when `ESP_IDF_SDKCONFIG_DEFAULTS` is exported —
   which happened in the developer's interactive shell but not in agent/cron
   builds. Verify by grepping the *generated* sdkconfig under
   `target/xtensa-esp32-espidf/release/build/esp-idf-sys-*/out/sdkconfig`,
   never by trusting the defaults file.

**Rules:**
1. After any IDF major-version bump, diff every `CONFIG_*` name you set
   against `idf.py menuconfig`'s current naming; renames fail *silently*.
2. CI/automation builds must pass `ESP_IDF_SDKCONFIG_DEFAULTS` explicitly
   (or vendor it in `.cargo/config.toml` `[env]`), and the build should assert
   the generated sdkconfig contains the expected values.

---

## B5 — "Continue without NFC" turns reader death into silent tollgate failure
**Date:** 2026-08-25 · **Found in:** bolty-esp32 init path vs. observed rig state
**Class:** firmware robustness

bolty's init scans I2C and `log::warn!("MFRC522 not detected …; continuing
without NFC")` — then heartbeats normally. In this session that exact path hid
a months-long state where the stick ran bolty with the reader either absent or
unreachable, while everything *looked* healthy. A tollgate that can't read
cards is down, not degraded.

**Rules:**
1. Peripheral health belongs in the heartbeat line itself
   (`[HB] alive t=… nfc=ok|DOWN`), not just in boot-time logs that scroll away.
2. If a subsystem's failure is operationally fatal, prefer a distinct
   degraded state (LED + heartbeat field) over log-and-continue.

---

## B6 — 911E ≠ 91AE: only failed *authentication* feeds the lockout counter
**Date:** 2026-08-25 · **Found in:** wipe session, card 04C474FA967380
**Class:** card safety (extends docs/card-safety.md §6)

Empirically confirmed on NTAG424 DNA: `911E` (INTEGRITY_ERROR — bad command
MAC *inside* an authenticated session) does **not** tick the permanent
authentication-failure counter. `91AE` (AuthFailed) / `91AD` (AuthDelay) do.
During the wipe we made ~6 successful EV2 auths and 3 in-session 911E mistakes
with zero growth in auth delay; the card never slowed. The driver aborted on
first 911E, which is the right reflex — but recovery was simply "re-auth and
resume", not "wait out a delay".

**Rules:**
1. 911E after a successful auth = your secure-messaging implementation is
   wrong, not the key. Stop, fix the session crypto offline (B8), re-auth.
2. Never convert a 911E into key-guessing — guessing keys is what costs
   TotFailCtr (see AGENTS.md card-recovery notes on 043365FA967380).
3. Prove key candidates *offline first*: a single card tap yields `p`/`c`;
   AES-decrypt `p` under candidate K1 and CMAC-verify `c` under candidate K2
   (SV2 = `3cc300010080 || uid || ctr_lsb`). That pins all keys with **zero**
   on-card auth attempts.

---

## B7 — Truncated greps hide fields; read the full log line
**Date:** 2026-08-25 · **Found in:** same session
**Class:** data handling

`rg … | cut -c1-150` on the 2024-12-08 provisioning log trimmed the key dict
mid-K2, silently dropping **K3/K4**. The wipe was staged with K3=K4=zeros
("LNBits never sets them"), the card rejected the K3 change (`911E`), and the
first attempt halted half-wiped (safely — K0 changes last). The full line
sed -n '9099p' contained all five keys all along.

**Rules:**
1. When mining structured log lines for payloads, extract fields, never
   truncate: `cut` is for humans skimming, not for data capture.
2. A rejected ChangeKey for key N with XOR-CRC-validated old-key encoding is
   *proof* the staged old key N is wrong — treat it as a lookup error, not a
   card fault.

---

## B8 — Port crypto byte-for-byte, then pin it with reference vectors
**Date:** 2026-08-25 · **Found in:** boltwipe.py vs bolt-card-programmer (application of cross-project L1)
**Class:** crypto / wire-format correctness

Reimplementing the app's NTAG424 secure messaging in Python produced two bugs
that *only* byte-level comparison caught: (1) the SV construction XORs
hex-character slices — `RndA.slice(4,16) ^ RndB.slice(0,12)` is 6 bytes of
hex-string indexing, not byte-array slicing; (2) the npm `crc` module's
`crcjam` is CRC-32/JAMCRC = zlib CRC32 **XOR 0xFFFFFFFF**, not plain CRC32.
The method: run the *original* implementation (`app/utils/Cmac.tsx` +
`crypto-es` + `crc` from the bolt-card-programmer checkout) on fixed session
inputs (fixed TI, session keys, cmdCtr, old/new keys) to emit the exact
FS_RESET/K1–K0 ChangeKey APDUs, then diff the port against those bytes.
Generator kept at `bolt-card-programmer/refchangekey.js`.

**Rules:**
1. Any port of a wire-format crypto implementation ships with a fixture test
   that asserts full APDU bytes against output from the original code.
2. Assume every "crc32" in a foreign codebase is a *variant* until you've
   read the polynomial/init/xorout/reflection parameters.

---

## B9 — Board bring-up code belongs in a shared crate, not per-app copies
**Date:** 2026-08-25 · **Found in:** recover_i2c_bus existing in bolty, missing in ccid-firmware-rs
**Class:** architecture

bolty-esp32 has `recover_i2c_bus()` (9 SCL pulses to free a stuck-slave SDA)
plus board-variant pin tables; ccid-firmware-rs — same board family, same
MFRC522 — had neither and its I2C init died to a stuck bus on first boot. The
fix was copy-paste *from* bolty. Both firmwares also consume `mfrc522-pcd`
(the shared transceiver crate this repo exports); the bring-up layer around it
(bus recovery, pin maps per board variant, MFRC522 re-init loop) is the part
that keeps diverging.

**Rules:**
1. Anything a second firmware on the same hardware had to copy should be
   promoted into the shared crate (`mfrc522-pcd` or a `board-support` crate):
   bus recovery, board pin tables, init-retry policy.
2. Divergence between two firmwares' bring-up sequences is a bug in the
   architecture, not in either firmware.

---

## B10 — Flashing the FT232 rig: esptool@115200, RTS-pulse resets, unbind/rebind recovery
**Date:** 2026-08-25 · **Found in:** same session (extends flash_and_test.sh notes)
**Class:** ops / tooling

Working recipe on the ai-legion-small rig, complementing the FTDI-wedge
warnings already in `ccid-firmware-rs/firmware/esp32-ccid/flash_and_test.sh`:

- esptool at 460800 is unreliable here (`chip stopped responding` mid-write,
  also broke `read_flash`); **115200 is solid** — 240 KB app in ~13 s.
- esptool's `--after hard-reset` leaves the ESP32 sometimes not executing the
  new image; `--after no-reset` + a manual RTS pulse (assert 150 ms, release)
  gives a clean, capturable boot from t=0.
- A wedged/hung USB state recovers with kernel unbind/rebind of the device
  (`echo 1-1 > /sys/bus/usb/drivers/usb/unbind`, wait, `bind`) — no physical
  replug needed over SSH.
- Stop pcscd before flashing (it holds the port); after flashing, wait out the
  firmware's NFC init (~6 s) *before* restarting pcscd, or its probe fails and
  the reader stays unregistered until the next restart.

**Rules:**
1. Prefer 115200 for anything that must succeed unattended; use high baud
   only for interactive speed.
2. Reset the target yourself (RTS pulse) and capture from t=0 — "flash
   verified" ≠ "new firmware is running".
