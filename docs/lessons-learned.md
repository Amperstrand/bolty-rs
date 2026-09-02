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

---

## B11 — FT232 open/close wedges: one persistent owner, ModemManager off the port
**Date:** 2026-08-25 · **Found in:** HIL scripting against the M5Stick rig
**Class:** host tooling / reliability

Every open()/close() of the FT232 USB-UART fires DTR/RTS TIOCMSET
transitions that corrupt this bridge's USB state machine — the device
disconnects from the bus (11 events in the lab kernel log, timestamps
matching every debugging session) and only a USB rebind recovers it.
Compounding it, ModemManager probes each new ttyUSB enumeration and races
real clients for the port. Symptom: the first open after a rebind works,
the second silently dies.

**Rules:**
1. The tty has exactly ONE owner, opened once per boot: `bolty-console`
   (tools/hil/) serving a unix socket. Tooling talks to the socket, never
   to /dev/ttyUSB*.
2. udev rule 99-bolty-stick.rules sets ID_MM_DEVICE_IGNORE (box has no
   modems) and power/control=on.
3. DTR/RTS are never touched after the daemon's single open.

## B12 — Anonymous taps need deterministic keys; picc is the live-URL getter
**Date:** 2026-08-25 · **Found in:** burn_cycle against boltcardpoc.psbt.me
**Class:** card lifecycle / service integration

A percard-CSV burn is cryptographically valid (p decrypts to the UID, CMAC
verifies — proven offline) yet the worker answers 400 "unable to decode
UID": routing an anonymous tap requires knowing the UID to pick the CSV
row, and the row to decrypt the UID. Deterministic issuer keys
(0000…0001, v1) are the anonymous-tap path; the same burn with them
yields HTTP 200 withdrawRequest end-to-end. Also: the `url` console
command is a setter only — the live substituted URL comes from `picc`
(`sdm=ok uid_match=true`, ndef= line).

**Rules:**
1. Cards meant for anonymous first-tap service get deterministic burns.
2. HIL assertions check `sdm=ok` + `uid_match=true` (this build prints
   that, not `mac=true`), and extract p=/c= from picc output.

---

## B13 — Three ways a lab stick plays dead (DTR/IO0, stale tty names, pcscd fatality)
**Date:** 2026-08-25 · **Found in:** ccid-firmware role-switch audit on the M5Stick rig
**Class:** host tooling / hardware debugging

An entire afternoon of "firmware freezes at first I2C transaction" —
across every build including the known-good binary — was none of those.
Three stacked host-side causes:

1. **RTS-pulse reset without clearing DTR**: pyserial asserts DTR on
   open; on this board family DTR→IO0, so DTR-high + an RTS (EN) pulse
   parks the ESP32 in download mode. Symptom: boot logs, then eternal
   silence that perfectly mimics a hang. Always `s.dtr = False;
   s.rts = False` before pulsing RTS. bolty-console now settles lines to
   neutral once at open.
2. **Stale `/dev/ttyUSBx` in configs**: USB rebinds re-enumerate the
   stick to a different tty number. Use the by-id path everywhere
   (daemon, pcscd reader.conf, scripts).
3. **pcscd exits fatally on a missing DEVICENAME** (status 1, repeated
   → systemd start-limit-hit → "Access denied" for clients). A disabled
   serial reader config must not reference a device that can vanish.

**Rules:**
1. Before blaming firmware, verify the chip is actually running: clear
   DTR/RTS, pulse reset, and watch for the full boot banner ending in
   your app's first log line.
2. Control-line state after pyserial open is ASSERTED by default — that
   is a valid download-mode request on these boards, not a neutral state.
3. Device paths in any daemon/config that survive reboots must be by-id.

---

## B14 — A preventive power-cycle recommendation is a bug in your mental model
**Date:** 2026-08-25 · **Found in:** post-B13 closeout of the role-switch audit
**Class:** hardware debugging / process

After B13's fixes landed, the session's final report still recommended "one
physical cold-unplug of the stick to clear any lingering MFRC522 state."
That was unnecessary — and it is instructive exactly why:

1. The stuck-slave state that motivates cold power-cycles was **never
   observed**: every boot's `recover_i2c_bus` logged `SDA high, bus OK`.
   All afternoon "hangs" were 100% the DTR/IO0 download-mode trap (B13) —
   a host-side cause, with the reader hardware healthy throughout.
2. The MFRC522 shares the stick's always-on USB rail. It has NOT been
   power-cycled in days, yet bolty reads `nfc=ok` and the CCID role
   completes card transactions (verified 2026-08-25, both roles, twice).
3. Every esp32-ccid boot now runs bus recovery + 50 ms settle + a bus
   probe before the first MFRC522 access — each boot is itself a
   self-healing attempt.

**Escalation policy (reactive, never preventive):** physically unplug ONLY
when a boot log prints `i2c recovery: SDA still LOW` after the 9 SCL
pulses — that is the one reader state software cannot clear.

For the record: the "module is marginal at 400 kHz" claim in
ccid-firmware-rs 244a309 was an artifact of the same confounded debugging
(the 08:06 known-good build ran 400 kHz all morning). The committed
100 kHz bring-up stays as deliberate parity with bolty's production
configuration — the RF side runs 106 kbps, so the I2C rate is not the
bottleneck — not as a proven-necessary fix.

**Rules:**
1. Recommend a hardware action only with a positive hardware-state
   observation behind it (e.g. an actual `SDA still LOW`), never as a
   residual "just in case" from a superseded theory.
2. When a root cause is found, sweep every earlier recommendation that was
   derived from the confounded theory — including your own.

---

## B15 — An echo-only CI job is worse than no CI job
**Date:** 2026-08-27 · **Found in:** esp32-check.yml stub vs REST job API breakage
**Class:** CI / process

`esp32-check.yml` "verified" the firmware by printing the commands it would
run. It looked green on every PR for months while the firmware target never
compiled anywhere — the REST job API merged with four compile errors, and the
partition-table breakage (B4-adjacent) shipped invisible. The stub even echoed
the *wrong* commands (workspace-root invocations that can't see
`apps/bolty-esp32/.cargo/config.toml`).

**Rules:**
1. A CI job that cannot fail is a lie with a green checkmark — delete it or
   make it real; never leave it as documentation theater.
2. Local hooks (pre-push builds) protect one machine; only the shared runner
   protects every contributor. Both are needed.
3. When replacing a stub, run the real thing once before trusting it — the
   first esp32-check run on GitHub runners is still pending at B15 time.

## B16 — Unused-result warnings on dispatch calls are behavioral bugs, not noise
**Date:** 2026-08-27 · **Found in:** REST /api/keyver and /api/inspect
**Class:** API correctness

Both handlers computed `let result = with_state(...)` and dropped it, always
returning `{"ok":true,...}` — including on authentication failure. The
compiler had been pointing at exactly this (`unused variable: result`) for
weeks. Any client using /api/keyver to check key state got a lying 200.

**Rules:**
1. An unused dispatch/operation result in an HTTP handler means the response
   does not reflect the operation — treat the warning as a bug report.
2. Match every workflow dispatch to the respond-with-result pattern (see
   `handle_diagnose`) — one shape for all handlers, no bespoke omissions.

## B17 — Verify hardware on committed source, or stamp provenance explicitly
**Date:** 2026-08-27 · **Found in:** 2026-08-27 known-good stamping

The burn-cycle verification ran on a build whose REST fix was still
uncommitted; the "known good" binary therefore had no commit sha of its own
until the fix landed minutes later. The stamp had to say "HEAD + uncommitted
rest.rs at time of stamping" to stay honest.

**Rules:**
1. Commit first, then hardware-verify, then stamp — the stamp should name a
   commit that exists.
2. If verification must precede the commit, record the dirty state in the
   stamp (files + shas), never imply a clean provenance.

---

## B18 — A never-compiled feature has two layers of causes; un-gating one can break every build
**Date:** 2026-08-27 · **Found in:** ble feature bring-up (commits 5011a97)
**Class:** dependency matrix / build configuration

The `ble` feature had never compiled, for two stacked reasons invisible from
bolty's own tree:

1. The `[package.metadata.esp-idf-sys.sdkconfig]` BT table was **silently
   ignored** by esp-idf-sys 0.37.2 — the generated gen-sdkconfig.defaults
   carried 0 CONFIG_BT lines, so `esp_idf_svc::bt` stayed cfg-gated off and
   every BLE error surfaced as "module not found" rather than "BT not built".
2. With BT forced on via sdkconfig.defaults, the esp-idf-svc fork's bt module
   itself fails: it needs ESP-IDF ≥5.3 symbols (`esp_ble_conn_params_t`,
   `esp_ble_gatt_creat_conn_params_t`) absent from the pinned v5.2.3. And
   because Bluedroid un-gates the bt module for EVERY configuration, the
   wifi/rest/ota builds broke too — not just the ble feature that needed it.

**Rules:**
1. A cargo feature that never compiled anywhere is a CI gap first and a code
   bug second — the CI matrix must build every config the repo ships.
2. Global sdkconfig flags un-gate dependency code for ALL build configs.
   Before committing such a flag, build every configuration, not just the
   feature that motivated it.
3. Dependency-matrix mismatches (svc fork ↔ IDF version) are diagnosed by
   grepping the dependency's source for the missing symbols against the
   vendored SDK headers — not by reading app code.
4. When a feature is blocked upstream, commit the groundwork (commented
   config block, corrected constants, CI placeholder) with the unblock
   conditions written next to it — the next session starts at the blocker,
   not at zero.

## B19 — Forks are rev-pinned or they will drift; unify by union, not by copy

Three vendored/forked dependencies (mfrc522, iso14443, ntag424) were unified
onto canonical `ai-experiments` revs in one day. The playbook that worked
twice: (1) diff the divergent copies and UNION the patches (both sides'
fixes), (2) push the union to the canonical fork, (3) rev-pin EVERY consumer
(bolty workspace deps AND ccid's direct + transitive specs), (4) delete the
vendor trees and `[patch]` tables.

**Rules:**
1. A branch-float spec (`branch = "ai-experiments"`) is drift waiting to
   happen; a rev pin is the only stable form. Policy: `docs/fork-policy.md`.
2. A transitively-consumed git dep (e.g. mfrc522-pcd@<bolty-rev> resolving
   its workspace iso14443 spec) must match the direct consumer's spec
   URL+rev EXACTLY — two specs resolving the same crate = two packages =
   type conflicts that only appear at link time.
3. Align the transitive provider's pin FIRST (bump bolty), then the
   consumer's direct pin (ccid) in a follow-up commit — never copy a branch
   spec to "match today".
4. `cargo update` (full) re-resolves everything and dies on unrelated dead
   branches (stm32f469i-disc `sdio-support`); use targeted
   `cargo update -p <pkg>` after manifest edits.

## B20 — Reusable CI workflows: four sharp edges in one adoption

The shared `rust-embedded.yml` (workflow_call, in amp-embedded-common) took
four fixes to run green on its first external consumer.

**Rules:**
1. `secrets: inherit` belongs in the CALLER's job — under the callee's
   `on.workflow_call:` it is a validation error that kills every run at 0s
   with no CLI-visible message. actionlint finds it instantly.
2. Clippy lint surface is a convention: this ecosystem lints lib/bins
   (`cargo clippy -- -D warnings`), NOT `--all-targets` — test code under
   workspace lints (indexing_slicing, unwrap_used) drowns the consumer.
3. apt packages must install in every compiling job — clippy links pcsc-sys
   exactly like tests do.
4. Pin the callee by full SHA (`uses: Amperstrand/amp-embedded-common/.github/workflows/rust-embedded.yml@<sha>`):
   run **reruns do not re-resolve `@ref` reusable workflows**, so a callee
   bugfix is invisible to a rerun and to same-second racing pushes.

## B21 — Reproducible ESP-IDF images: empty the clock, pin the stamp

`CONFIG_APP_REPRODUCIBLE_BUILD=y` (ESP-IDF v5.2.3) empties the app
descriptor's `__TIME__/__DATE__` and adds debug prefix maps — that alone
makes two builds of one commit byte-identical. A controlled stamp
(`BOLTY_BUILD_EPOCH` > `SOURCE_DATE_EPOCH`, default "0") is embedded via
build.rs `cargo::rustc-env` + `rerun-if-env-changed` so CI can trace images
without breaking determinism. Acceptance is the three-hash proof: A==B
(same env, one clean rebuild apart) and C≠A (deliberately different epoch).

## B22 — Tests that run nowhere rot invisibly

The 22 firmware unit tests (#63) had drifted from the API (`Command::Ota`
grew `signature`, `BoltyConfig` grew `force_unsafe`, the `{mac}` SDM gate)
precisely because no CI ever executed them. Un-gating the pure-logic
modules (`mod commands; mod service; mod workflow;` compile on host) plus
one host-test job in esp32-check revived them — repairs were test-only,
plus one NEW test locking the `{mac}`-refusal gate the rot hid behind.
An echo-only CI job is worse than none (B15); a never-run test is a lie
about coverage.

## B23 — One repo, two agents: record the coexistence risk at first sight

A parallel session was committing to microfips mid-plan (l2cap dialect
work, author "Sisyphus" vs our workers' "Amperstrand"). The T4 worker saw
uncommitted foreign WIP (l2cap_host.rs) and left it untouched with a ledger
note — that note is what let the final audit attribute the later CI-red to
the concurrent commits, not ours. When you see dirty foreign state in your
working repo: don't clean it, don't commit it, RECORD it (path + mtime +
what it looks like) and exclude it from your diffs.

## B24 — LLM-driven HIL verification is a one-time cost; encode it into a make-driven framework

The 2026-09-01 hardware verification (burn→lock→tap→gated-wipe→blank) cost
~40 tool calls driving individual commands. Encoded as
`tools/hil/tests/test_burn_lock_wipe.py` + the `hil/` framework, the same
cycle runs via `make test-hil` in ~3 seconds. The framework's safety design
(cards.toml registry, placement-flexible discovery, role_guard context
manager) captures every hard-won lesson from the manual sessions.

**Rules:**
1. The card registry (UID + ops), not physical reader placement, is the
   safety contract — cards move in real labs.
2. Role switches live in a context manager; the finally block restores
   even under interruption (proven in the field).
3. Preflight is composable and severity-aware: absent secondary reader =
   warning (degraded run OK); absent target card = hard fail.
4. The difftest needs its own make target and 30-min budget — don't try to
   squeeze it into a quick suite.
