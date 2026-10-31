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

## B25 — labgrid 26.0's exporter surface fails SILENTLY in three ways

Getting the ACR1252 + M5Stick serial properly onto the coordinator (2026-09-02,
issues #78/#79) surfaced three traps, each of which produces a running-looking
exporter with broken resources:

1. **Class-key confusion**: the exporter YAML key must be a class in labgrid's
   `exports[]` map (`USBSerialPort`), NOT the client-visible name
   (`NetworkSerialPort`). A wrong name silently rides the plain
   `ResourceEntry` fallback: no `SerialPortExport` wrapper, no ser2net on
   acquire, no `host` param — client-side expansion then dies with
   `missing 1 required positional argument: 'host'`. The rig's serial export
   had this bug since inception; nothing consumed it via labgrid, so it never
   surfaced. Deliberate fallback use (our ACR1252 acquisition token) needs a
   client-side class registered via env-yaml `imports:` (see
   `tools/hil/labgrid_resources.py`) or place expansion dies with
   `unknown resource class`.
2. **Wire format**: exporter→coordinator params serialize to a flat protobuf
   `MapValue` (bool/int/float/string only). A udev `match` dict can NEVER
   cross it — "cannot translate OrderedDict to MapValue" is a design limit,
   not a syntax error to fix.
3. **Jinja**: exporter YAML goes through Jinja2 with
   `line_statement_prefix="#"` — `# ` comment lines are STATEMENTS at any
   indentation and crash the exporter ("unknown tag"). Comments must be
   `##`. Cost one crash-restart loop to learn; documented in the YAML.

Also: ser2net must be installed (the wrapper spawns it per-acquire and reaps
it on the exporter poll cycle — the console daemon survives both); coordinator
restarts wipe in-memory places → `make labgrid-place`; the coordinator binds
ONLY 192.168.13.221:20408 (not 127.0.0.1) and this host has no mDNS resolver.

## B26 — cross-cutting setup that must precede plugin fixtures belongs in pytest_sessionstart

The labgrid plugin requires the place ACQUIRED before its env/target fixtures
expand resources — but pytest fixture-store ordering does NOT guarantee a
conftest fixture (our rig_lock) runs before plugin-registered fixtures
(env/target), regardless of test-signature order. Symptom: expansion fails on
unacquired-place params even though the lock fixture "should have run first".
Fix: acquire in `pytest_sessionstart` (conftest hooks DO run before fixture
instantiation) and have rig_lock defer to it when the --lg-env path is active.
General rule: when a conftest fixture must ordered-before a plugin fixture,
don't fight the fixture store — move the setup into a session hook.

## B27 — esp_rom_crc32_le is neither zlib nor zlib^FF: read the ROM host source

The otadata entry CRC (bootloader validates CRC32 of the 4-byte ota_seq
field) took three hardware iterations: zlib.crc32(seq) rejected,
zlib.crc32(seq)^0xFFFFFFFF rejected, both written to real flash and both
met with `ota data partition invalid → factory fallback`. The
authoritative algorithm lives in IDF's own host implementation
(components/esp_rom/linux/esp_rom_crc.c): `crc = ~crc; table-loop;
return ~crc` — invert-in AND invert-out. With init 0xFFFFFFFF that nets
out to a third value none of the standard libraries produce directly.
Rule: when a ROM function's exact semantics matter, replicate the ROM's
own host twin verbatim (it exists precisely so linux-target builds
match), and pin the bytes with a golden test before touching hardware.
The boot log over UART (pyserial + RTS pulse) is the fastest
bootloader-verdict oracle — one reset, six seconds, no flashing.

## B28 — modular and DRY: shared logic lives in ONE crate, projects inherit (owner directive 2026-09-11)

The 2026-09-11 micronuts QR-rig session proved the cost of violating
this: micronuts firmware hand-rolled the GM65 continuous-mode dance,
the silent-buzzer policy, and the ACK-leak strip because the knowledge
lived in gm65-scanner's examples and issues instead of its API — and
the first hand-rolled SETTINGS write beeped the lab (buzzer is bit 6;
the composer guessed the bits).

Rule (owner directive, applies to every Amperstrand MCU project):
- Domain logic has exactly one home. QR-scanner logic belongs to the
  gm65-scanner crate (`ScanPolicy::start_scanning`, sanitize-in-read,
  module-heal commands) — consumers pin the crate and write ZERO
  module lore. bolty-rs consumes ntag424-fork primitives the same way.
- Board-level glue belongs in the BSP crates, not per-project firmware:
  screen/display settings for the STM32F469 (embassy-stm32f469i-disco)
  and the ESP32 boards (CYD, Lilygo S3) live in their BSPs so every
  project driving that board inherits fixes.
- Heal/recovery commands are crate-or-BSP surface, never per-project
  copies (the gm65 deep_sleep_reboot Tier-A heal is the model).
- Fix it once upstream; every project inherits the benefit. When a
  consumer discovers itself re-implementing module/board lore, that is
  a bug in the crate — file it, promote the API, delete the local copy
  (the micronuts adoption commit is the template: net −20 lines).
- Audit for old/deprecated/legacy/dead code when touching a crate;
  deprecate the old path in the same commit that ships the new one
  (gm65's enter_continuous_mode deprecation).

## B29 — GM65 deep wedge: software heals are a LADDER, not a panacea; shared-bench sessions must check-in AND check-out (2026-09-13)

Evidence: micronuts physical-loop session 2026-09-13; gm65-scanner soak
2026-09-11 (#92, QR-RIG-SESSION-PLAN); gm65-scanner AGENTS.md wedge
taxonomy; micronuts firmware factory_heal (0x14) failing live.

**The wedge taxonomy** (three classes, distinct recovery requirements):

| Class | Symptom | Software recovery | Physical recovery |
|---|---|---|---|
| Decode fatigue (#92) | UART ACKs, zero decodes, watchdog climbs | Idle time; deep-sleep (0x13) sometimes | board power-cycle (always) |
| Settings corruption | init VERIFY fails; register writes ACK but read back wrong | factory_reset ladder (0x14) usually | board power-cycle (always) |
| Deep wedge (ROM state) | init fails at EVERY step; even factory_reset doesn't restore init | **NONE PROVEN** — 0x13 and 0x14 both fail | board power-cycle (only known fix) |

The 2026-09-13 micronuts session hit class 3: `ScannerTrigger`
(raw UART set_aim) returned OK, proving power + UART alive, but `init()`
failed across 3 ST resets (each running the firmware boot-heal =
deep-sleep + retry), 60 s of idle polls, AND the full 0x14
factory-heal ladder. The module's internal state machine was wedged
below the register layer. **A GM65 that ACKs UART but fails init after
factory_reset needs its power rail cycled — stop burning session time
on software heals.**

**Why we kept hitting this**: each "fix" addressed the PREVIOUS session's
wedge class. The 2026-09-11 session added the boot-heal (deep-sleep) for
class 1, then the factory-heal for class 2, then documented "expect idle
recovery by morning" for what was actually class 3. The ladder was
complete for classes 1-2 but the session notes read as if ALL wedges
recover with time. They do not.

**Rules:**

1. **Bench check-in/check-out protocol**: every session that acquires
   shared-bench hardware runs a health probe FIRST (CYD `ID`, GM65
   `ScannerStatus`, F469 `swap gate --selftest`) and records it. At
   session end, re-run the probe and leave the bench in a known state.
   A session that finds the bench degraded names the degradation in its
   session notes — silent handoffs are how wedges compound across days.
2. **Recovery matrix, not "try everything"**: when a module misbehaves,
   classify the wedge (ACKs? decodes? init?) and apply the matching
   fix. If the factory ladder (0x14) fails, escalate to physical
   power-cycle immediately — do not re-run software heals hoping for a
   different result.
3. **Heal ladders must document their CEILING**: every software-recovery
   path needs a "this is the deepest state I can fix" line. The
   factory-heal now has one: it cannot fix a module whose init fails
   after factory-reset (class 3). Writing "expect idle recovery" without
   distinguishing class 3 from class 1 is how the next session burns
   an hour.
4. **Shared-bench hardware is a commons**: the CYD was found running
   foreign firmware (wifi console debris); the GM65 was found wedged.
   Neither was the current session's fault; both cost current-session
   time. The check-in probe catches both in under 60 seconds. Treat it
   like `git status` at the start of a session — non-optional.

**Applied across projects:**
- gm65-scanner: AGENTS.md wedge table + README recovery matrix
- micronuts: AGENTS.md bench protocol reference + tools/hil/bringup.py
  becomes the check-in gate
- tollgate-lab (owner of the bench tooling): the check-in/check-out
  helpers live here so every project inherits them without copying

## B30 — silent-wrong-firmware class on this bench: THREE independent ways a cargo build lies (2026-10-12)

The ESP-IDF v5.5.5 unification session (bolty-rs + ccid-firmware-rs, same
day) hit three stacked traps; each produced a build that LOOKED successful.
ccid had already documented trap 1 (their AGENTS.md, bench lost a full day);
bolty reproduced it and then found two more.

1. **Stale esp-idf-sys state ignores the IDF pin.** With a shared/global
   `CARGO_TARGET_DIR`, the esp-idf-sys build script resolves the workspace
   by popping OUT_DIR six levels — inside the target dir — and silently
   builds whatever IDF the stale state holds. Symptom here: manifest said
   `tag:v5.5.5`, binary strings said v5.2.3 (also: `/root/.cargo-target`
   holds ccid's artifacts with ITS v5.5.1 — two workspaces sharing one
   esp-idf-sys build dir cross-contaminate). Fix: `CARGO_WORKSPACE_DIR`
   export + per-repo `CARGO_TARGET_DIR` + `ESP_IDF_SYS_ROOT_CRATE` (virtual
   workspace has no resolve root without it). All encoded in
   `apps/bolty-esp32/build.sh`.
2. **`esp_idf_version` bumps do NOT rerun the build script.** Nothing
   declares rerun-if-changed on manifest metadata — after a bump you MUST
   `--clean-sys` (delete the `build/esp-idf-sys-*` dirs). Same class:
   sdkconfig-defaults switches.
3. **Relative sdkconfig paths resolve against the WORKSPACE root, not the
   crate.** `ESP_IDF_SDKCONFIG_DEFAULTS=sdkconfig.defaults` handed to a
   build from `apps/bolty-esp32/` resolves to `<workspace>/sdkconfig.defaults`
   — which does not exist — and embuild DROPS it silently: the build runs on
   bare embuild defaults (no 4MB flash, no HTTPS server, no watchdog cfg)
   and still compiles. The `[env]` entry in `apps/bolty-esp32/.cargo/config.toml`
   with `relative = true` is the resolution mechanism, not documentation —
   do not delete it. Variant files (`sdkconfig.defaults.ble`) must be passed
   as ABSOLUTE paths (build.sh does).

**Countermeasure (build.sh gates):** every build verifies (a) the resolved
`esp_idf_dir` ends with the manifest tag, and (b) `esp-idf-build.json`'s
`sdkconfig_defaults` list contains the requested defaults file — both fail
LOUDLY with the `--clean-sys` instruction. `strings <binary> | grep v5\.`
is the zero-tooling spot check.

**Also learned (same session):** cargo `[env]` values shadow/shapes reach
the build script only after [env]→process-env precedence is considered —
verify empirically, not from memory, before relying on either direction.

## B31 — ccid-firmware-rs port session: what crossed projects dry (2026-10-12)

Ported from ccid-firmware-rs @ f2a250b (182-commit window, 2026-10-02→10-12;
full port-candidate matrix built first — see the session's explore output):

- **MFRC522 field dwell + activation ladder** (ccid 89382e6 + 9fd1626):
  `prepare_for_activation_with_delays` (50 ms field-off dwell / 5 ms settle,
  DelayNs-injected; legacy no-delay path preserved for host tests) +
  `Mfrc522Transport::activate_with_delays` (4 × prepare→settle→WUPA, then
  full activation; retry budget targets the flaky RF half). Service layer
  injects `FreeRtos::delay_ms` as a `fn(u32)` hook — busy-waits through
  ≥1 ms dwells trip the task watchdog (ccid #63/#80 root cause).
  Bench evidence task: tools/hil/tests/test_activation_ladder.py.
- **pn7160-nci as a git dependency** (B28 doctrine — the crate keeps ONE
  home in ccid-firmware-rs; bolty inherits at rev f2a250b) +
  `crates/bolty-pn7160`: the ntag424::Transport bridge, host-tested against
  a byte-exact scripted NCI mock. NOT yet wired into firmware (needs the
  esp32 i2c_master transport port — future work with the vendored-hal
  legacy-i2c gating).
- **tools/hil conftest hardening** (ccid bbc8f6a/54524aa/fe17ea5): labgrid
  place INHERITANCE ("You have already acquired" by our identity = success,
  inherited places are never released at teardown), OSError-guarded path
  resolution (stat() on root-owned dirs raises EACCES, not ENOENT —
  collection-time helpers must never raise), best-effort release. Locked by
  tests/test_conftest_hardening.py.
- **Not ported, deliberately:** pn7160-nci's ESP32 i2c_master transport
  (needs ccid's vendored esp-idf-hal legacy-i2c gating — revisit when bolty
  gains a PN7160 board feature); SPP/classic-BT (no pcscd in bolty);
  serial_ports.py dynamic detection (bolty's console goes through the
  unix-socket daemon, no hardcoded ttys in python tooling).

**BLE verdict (dry, 2026-10-12, IDF v5.5.5):** **COMPILES.** The esp-idf-svc
0.52.x fork's bt module builds against IDF v5.5.5 once the BT sdkconfig
actually reaches the build — the earlier "blocked on the esp-idf-rs
generation" analysis was an artifact of the B30.2/B30.3 delivery traps, not
a real API gap. Full `board-m5stick,ble` firmware built with both build.sh
gates green (IDF pin + sdkconfig consumption verified); two never-compiled
ble-gated bugs were fixed along the way (heapless::String type confusion in
`process_ble_command`, and a `MutexGuard` reborrow in its dispatch path).
RADIO behavior (advertising, GATT, pairing) remains unproven until Phase 3
of docs/hil-runbook-2026-10-13.md runs on hardware.

## B32 — ACR1252 CCID wedge has TWO classes; the shallow one heals through pcscd reconnect — recovery is a ladder, and the trigger is us (#101, 2026-10-19)

Evidence: 2026-10-19 bench day — audit-log burn/wipe cycle ~12:28 local;
pcscd restart 12:47; wedge 13:10:56 (`ccid_usb.c WriteUSB() write failed
(1/122): LIBUSB_ERROR_NO_DEVICE` + `InterruptRead() libusb_submit_transfer
failed: LIBUSB_ERROR_NO_DEVICE`); dmesg shows **no USB disconnect** — the
reader (072f:223b, usb 1-4) stayed enumerated; `lsusb -v` control-transfer
probe answered; live pyscard probe ~14:35 completed connect → T=1 → ATR
`3B 81 80 01 80 80` → vendor attribs **without any replug**. Deep-wedge
contrast case: #101 (owner physical replug required). Access audit: lsof
showed ONLY pcscd holding `/dev/bus/usb/001/*` — the labgrid `ref-acr1252`
export is match-only (no standing usbfs claim, no dual-access cause).

**Signature** (how to recognize it in 30 seconds): pcscd journal logs
`LIBUSB_ERROR_NO_DEVICE` on WriteUSB/InterruptRead, `lsusb` still lists the
reader, dmesg has NO `usb disconnect` line for it, and `lsusb -v` (real
control transfers) answers. That is a hung CCID bulk pipe under a live
control endpoint — not a USB-level device loss.

**The wedge taxonomy** (B29 doctrine applied):

| Class | Symptom | Recovery |
|---|---|---|
| Shallow (2026-10-19) | NO_DEVICE under pcscd; control ep alive; no kernel disconnect | close all client sessions → `systemctl restart pcscd` → reconnect. **Proven: reader fully functional hours later, no replug.** |
| Deep (#101) | bulk pipe hung through pcscd restart attempts | **physical power removal only** (replug; the AGENTS "what does NOT work" list applies — pcscd restart, unbind/bind, SCARD_UNPOWER_CARD do not cut VBUS on this reader) |

**Recovery ladder** (escalate in order; stop at the first pass):

```bash
# 0. PROBE (also the B29 check-in probe for this reader — no card auth,
#    connect+status only):
python3 -c "
from smartcard.scard import *
rc, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
rc, h, p = SCardConnect(ctx, 'ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 03 00',
                        SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1)
rc, rn, st, pr, atr = SCardStatus(h)
print('connect+status:', SCardGetErrorMessage(rc), 'ATR:', atr.hex())
SCardDisconnect(h, SCARD_LEAVE_CARD); SCardReleaseContext(ctx)"
# 1. SHALLOW HEAL: end every session holding the reader, then
systemctl restart pcscd        # then run the probe again
# 2. USBDEVFS_RESET ioctl on /dev/bus/usb/001/<dev> (UNTESTED here —
#    record the result the first time it's tried)
# 3. authorized toggle: echo 0 > /sys/bus/usb/devices/1-4/authorized; \
#    sleep 2; echo 1 > /sys/bus/usb/devices/1-4/authorized  (UNTESTED here)
# 4. POWER REMOVAL: physical replug — the only deep-class recovery on
#    this bench (owner decision 2026-10-19: no switched-power hub).
```

**Wedge anatomy (2026-10-23 deep-wedge post-mortem, USB-level evidence)**:

Why the device dies and why only power removal revives it —
1. The ACR1252 is a single-pipeline MCU firmware: CCID slot state
   machine + autonomous RF polling (card-detection notifications ride
   the interrupt-IN pipe; that is how pcsc hotplug works).
2. Host-side URB cancellation mid-transfer (pcscd exit/restart, client
   kill, cancelled exchange) can strand the device holding an
   un-collected bulk-IN response / pending notification. ACS firmware
   (documented across the ACR1xxx line for a decade) lacks a robust
   "host went away — flush pipeline" path; the state machine waits
   forever.
3. Pressure amplifiers pile onto the stalled pipeline: RF chaos on the
   antenna (a live foreign reader + battery + PCB stacked on it =
   detection thrash = interrupt notification storm) and repeated
   restarts (each restart is a fresh mid-flight-abort lottery).
4. Terminal state = FIRMWARE hang with the USB hardware block still
   alive: the device keeps bus-level behavior (stays in sysfs, no
   kernel disconnect) but stops answering enumeration-level requests.
   Proof from tonight: deauth/reauth (`authorized` 0->1) produced NO
   re-enumeration — a healthy device MUST re-enumerate with a new
   device number after that; it kept number 030 and emitted no
   descriptor exchange. `USBDEVFS_RESET` port reset (kernel-confirmed)
   equally cannot restart hung MCU firmware. Only VBUS removal re-runs
   the firmware from reset.

**Reader spacing rule (RF hygiene, from the 2026-10-23 sandwich)**:
two 13.56 MHz readers on one bench need >=15 cm side-by-side
(antennas coplanar — never facing each other) or >=30 cm in any
orientation; 0-5 cm antenna-facing is the mutual-destruction zone
(coupled fields + conductive mass detuning — a battery/PCB lying on
an antenna blanks it even powered-off). Nothing but cards on antenna
surfaces. Card read range is 3-5 cm, so separated readers cannot
cross-read each other's cards.

Causal chain tonight (journal-timed): matrix-session probe retry loop ->
5 pcscd restarts in 85 s (18:23:13-18:24:38) -> one restart cancelled a
transfer mid-flight on the ACR (aggravated by the stacked reader's RF
coupling) -> first "Not Found" 18:26:45 -> dropped from enumeration
permanently. The systemic fixes are the ones this bench now has: no
restarts outside pcscd-ctl/domain lock (tollgate-lab #15/#16; the
disturbing session queued its retrofit after this incident), graceful
harness teardown, and NO live reader on another reader's antenna.

**Ceiling** (B29 rule 3): steps 1–3 cannot fix a device that fails the
RESET/re-enumeration handshake — if the probe still fails after step 3,
it is the deep class; go straight to power removal, do not loop software
heals.

**The trigger is us**: the wedge follows CCID exchanges aborted
mid-bulk-transfer (NEW candidate trigger, 2026-10-23: sustained foreign
RF coupling with no CCID traffic at all — an M5stick was stacked on the
ACR1252's antenna for ~1h, its MFRC522 field coupling into the ACR's
front-end while heavy pcscd churn ran; the ACR wedged deep without a
single CCID exchange. Correlation, two candidate causes — attribution
stays open until a controlled repro) — harness timeouts/kills during card auth-delay (`91AD`)
windows when responses are legitimately slow, AND **pcscd restarts caused
by sibling bench sessions** (observed 2026-10-19: a concurrent M5Stick
flash session bounces the stick's USB on every flash step; socket-activated
pcscd re-inits (its config still carries the stick's `/dev/m5-ccid` serial
reader) and every restart aborts in-flight CCID exchanges bench-wide —
clients see `Service not available` gaps and `NO_DEVICE` bursts).
Prevention: keep the bolty-cli backoff+circuit-breaker discipline
(6d08cbb); HIL harnesses must tear down gracefully — never SIGKILL
mid-APDU; treat a 91AD card as slow, not dead; and coordinate stick-flash
sessions with reader sessions (they are not as independent as the place
model suggests — pcscd couples them).

**Firmware**: IFD_VERSION attrib reads `0.0.0.1` (v1.x line; exact build
string needs the proper Le in the FF 00 50 pseudo-APDU). No public ACS
changelog attributes a CCID-hang fix to any ACR1252U firmware; an upgrade
is owner-only (Windows updater from the ACS SDK), changes the reference
oracle (Phase-1 revalidation + provenance note required), and is
low-confidence.

**Update (2026-10-19, same day — owner decision + automation)**: the
switched-power hub was declined for this bench, so the deep class stays
**owner-replug-only** and prevention/early detection are load-bearing,
not optional. Automated: `tools/hil` conftest now runs the B32 probe as
a **check-in** the moment `rig_lock` grants bench exclusivity and a
**check-out** at sessionfinish (results in the run ledger's `acr_state`);
a wedge at check-in makes every `coupled_card_uid` test skip loudly with
the heal pointer instead of burning minutes on timeouts, and
`BOLTY_ACR_AUTOHEAL=1` opts into the shallow heal (pcscd restart — shared
infra, opt-in only). The probe itself runs in a killable subprocess — the
one mid-exchange kill that is safe by design. If wedges persist at this
rate, capture a usbmon trace of one and draft an ACS technical-support
report (owner-only channel).

## B33 — The "dead" ACR1252 was a config write, not a death: NVM auto-poll-off masquerades as RF failure across replugs AND host moves (#214, #208; 2026-10-25)

Evidence: 2026-10-22 22:22 local — the `cashu phone-vs-device` HIL session
(opencode log, `/tmp/opencode/phone-hil`) ran, labeled "quiet auto-poll":

    SCardControl(h, CM_IOCTL_SMARTCARD_DIRECT, toBytes("E0 00 00 23 01 00"))

— Set Automatic PICC Polling with setting 0x00 (API V1.17 §5.4.7:
**"The setting will be saved into non-volatile memory"**; doc default
0x8B). Intent: RF-silence the ACR while testing the phone against the
M5Stick. Consequence: from that moment the reader never polls → never
detects any card — through all three B32 wedge cycles, through every
replug, and through the host move to ai-legion-small. On 2026-10-25 the
reader (card `04c474fa967380` physically on the antenna) read back
`FF 00 50` → `90 3F` (param 0x3F: bit7 auto-poll=0, bit6 auto-ATS=0) and
`E0 00 00 23 00` → setting `0x00`. Two writes restored it:
`FF 00 51 FF 00` + `SCardControl(CTL_CODE(1), E0 00 00 23 01 8B)`; the
NTAG424 answered within one 250 ms poll cycle — 5/5 stable UID reads.
One 0x00 polling write flips BOTH register views (the FF 00 50 param
mirrors the polling state in this firmware) — the ATS-off bit piggybacks.

**Why two days of diagnosis went sideways (the confusion chain)**:

1. `90 3F` was misread as an "abnormal firmware response" — it is the
   NORMAL Get PICC Operating Parameter echo (`90 <param>`, §5.7.3), and a
   healthy reader returns the identical bytes for the identical command.
   The prior session's PDF copy was a broken 5 KB stub (the real manual
   is 1.2 MB; mirrors: elvantic.com / rpi4cluster.com / device.report —
   saved at `/tmp/opencode/acr1252u-api-full.pdf`).
2. "No card detection" was only ever tested against the S20 HCE phone —
   which had NEVER coupled, even before the poll-off write. The J3R180 /
   MIFARE detections quoted as "before the wedge" predate 22:22; a
   `printf` of a canned "ATR 3b8180018080" checkin line (found in the
   10-23 logs) was template output, not a live detection. No physical
   card was ever placed on the antenna after the write until 2026-10-25.
3. The B32 wedges (real USB hangs, 18:23–18:26 10-23) were blamed for a
   detection failure that had started ~20 h earlier. Wedge ≠ config:
   the wedge signature is hangs/NO_DEVICE (B32); the config signature is
   everything healthy + EMPTY forever. The 2026-10-24 #208 sweep
   ("all host readers empty of burn cards") was reading a poll-off
   reader as "no card placed" — the exact #208 blocker.

**The 30-second discriminator** (use before ANY "reader died" debugging):
`lsusb` shows it + `FF 00 48 00 00` returns the firmware ASCII + shared
connect answers instantly (even `NO_SMARTCARD`) + `FF 00 50 00 00`
returns `90 3F`-style → the reader is ALIVE; if the param bit7=0 or the
`E0 00 00 23 00` setting bit0=0 → config, not hardware. Restore is two
writes, no replug, no pcscd restart. On this pcscd/ccid stack the escape
route is `SCardControl(SCARD_CTL_CODE(1)=0x42000001, E0 …)`; the
CM_IOCTL_SMARTCARD_DIRECT (CTL 1960) from the ACS examples returns
0x8010001f here (verified live).

**ACR1252U facts worth keeping** (API V1.17 + web, zread had nothing —
not indexed):

- Transparent session (`FF C2 00 00` + DO `81` start / `82` end, §5.2.1)
  suspends auto-polling TEMPORARILY and restores it on session end — the
  correct tool for RF-quiet experiments; RF field on/off DOs `83`/`84`
  are volatile too. NEVER use E0 00 00 23 for quieting; it is NVM.
- `FF 00 50`/`FF 00 51` = get/set PICC operating param (bit7 poll, bit6
  auto-ATS, bit5 250/500 ms, bit4-0 tag types). Bench default 0xFF.
  MIFARE Classic detection requires auto-ATS=0 — that is why ATS was off
  in 0x3F; if MIFARE tests are needed, flip bit6 for the session and
  RESTORE (the check-out audit will flag it otherwise).
- Polling-setting defaults: V1.17 says 0x8B, V1.02 said 0x8F (bit layout
  also drifted: bit3 "activate PICC" → RFU, bit6 → NXP MIFARE selection,
  "firmware 111.1 and above"). Our V101.0 reader accepts 0x8B; either
  value has poll+activate on.
- Power-save reminder (§5.4.7): antenna-off-when-idle bits cut idle
  current 130→60 mA AND stop cards "warming up" on the antenna — nice
  for NTAG424 longevity on this bench.
- Firmware update path: the reader re-enumerates as bootloader PID
  072f:223D ("ACR1252 BL", per acsccid reader table); updater is
  Windows-only from the ACS SDK — owner-only, and it changes the
  reference oracle (B32 already ruled this low-confidence).
- acsccid (github.com/acshk/acsccid) is ACS's own IFD handler if the
  stock ccid driver ever lacks a reader; libnfc does NOT support the
  ACR1252U (nfc-tools/libnfc#658) — PC/SC only.

**Prevention (landed with this lesson)**: `tools/hil` check-in probe now
audits both NVM registers and returns state `cfg` (card-coupled AND
no-card variants both covered); check-in heals to defaults
automatically (no pcscd touch — safe where the B32 shallow heal is
opt-in; `BOLTY_ACR_CFG_HEAL=0` skips), check-out re-audits, and
card-consuming tests skip loudly with the restore pointer if drift
survives. The systemic contract (AGENTS.md): bench-reader NVM config is
SHARED bench state — sibling sessions mutate it invisibly and place
locks do not cover state that outlives the session; only hardware-read
audits (#209's bare-CLI gap is the same class) catch it. Restoration
duty: any experiment that writes reader NVM restores defaults before
releasing the place, or uses a transparent session instead.

## B34 — the 2026-10-26/28 hardware-incident wave: three latch classes and the levers that now exist (2026-10-31)

Three days, three hardware-latch failures, three DIFFERENT recovery
levers — the pattern is the lesson: **state that lives in a component
your resets don't touch survives your resets**.

1. **m5stick MFRC522 brownout latch (Oct 26 04:55)** — the reader
   vanished from I2C across every ESP32 POWERON reset because the
   AXP192 (a separate chip, VBUS-powered) never dropped the Grove 5V
   rail. Lever: the fw `grove off/on` console command (AXP192 EXTEN
   bit cycle, PR-landed with the bench fw) — remote, no hands. The
   reader revived and SURVIVED the next bench event without re-latching.
2. **nucula-c3 USB-Serial/JTAG TX→RX loopback latch (Oct 28 evening,
   issue #245)** — the peripheral echoes its own TX into RX; survives
   chip resets, flash erase, and USB bus re-enumeration (all
   VBUS-powered state). Only a VBUS drop (unplug/replug) cures it.
   Diagnostic tell: console commands come back as
   `unknown command: <binary garbage><your command>` — RX echo, not fw
   TX. Lever: none remote — 5 seconds of owner hands.
3. **Daemon-reopen DTR reset storms** — every bolty-console restart
   pulses DTR/RTS in a pyserial sequence the C3 reads as
   USB_UART_CHIP_RESET; a wedged device turns the crash-restart loop
   into a 6-second-cadence board-reset storm (38 resets observed).
   Levers (landed): same-fd stall retry in bolty-console +
   StartLimitIntervalSec/Burst on the c3 unit + the flight recorder
   (dated ms-stamped ring snapshots to /root/bench/incidents/ on any
   reset banner / panic signature / garbage line — this is now the
   primary forensic record, NOT journal archaeology).

Also from this wave: the Oct 26 "console garbage" first read as fw TX;
it was RX loopback echo. Check WHICH DIRECTION the bytes travel before
theorizing about emitters. And: bench events cluster at ~03:30–04:55
AM three nights running (Oct 26/27/28) — if something shares that
window's timer, it is worth an owner look.

## B35 — the global /root/.cargo-target: worktree builds lie about WHERE (2026-10-31)

`~/.cargo/config.toml` sets a host-global `target-dir = /root/.cargo-target`:
every worktree's build lands in ONE shared directory. Two consequences,
both bitten this week: (1) a "worktree-local" binary is a myth — always
`strings`/mtime-verify the artifact before a live test (a stale
bolty-cli from another worktree silently invalidated one interop run);
(2) parallel builds from different worktrees share fingerprints and can
evict each other's esp-idf-sys caches. This is the B30
(silent-wrong-firmware) class's host-side twin: same rule, same cure —
verify the artifact, not the command's exit status. `build.sh` in
apps/bolty-esp32 already pins a repo-local CARGO_TARGET_DIR; HOST
builds have no such guard.

## B36 — cargo tree --invert is BLIND to target-gated deps without --target all (2026-10-31)

`cargo tree --workspace -e normal --invert rand_core@0.9.5` printed
NOTHING for a dependency that demonstrably exists in the lock — its
consumers (stm32f4xx-hal → bolty-stm32) are target-gated, and plain
--invert resolves only the host target. This is how rand_core went
missing from the dependency-duplicates nine-base triage (#181, row now
added with evidence). Rule: duplicate/duplicate-triage evidence
commands must include `--target all`, or target-gated forks silently
drop out of the decision record.
