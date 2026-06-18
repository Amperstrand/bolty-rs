# Roadmap

## Completed

### Core Functionality
- [x] NTAG424 DNA full lifecycle: burn, wipe, diagnose, inspect, keyver, cycle
- [x] Standard-compatible SDM MAC (`[[{mac}` — empty input range)
- [x] Deterministic key derivation (verified across Rust/C++/JS implementations)
- [x] `preflight()` safety check before all write operations
- [x] Per-key version verification after burn/wipe
- [x] `--dry-run` mode for all write commands
- [x] `--confirm-uid` safety flag to prevent wrong-card operations
- [x] ESP32 burn derives keys from issuer key (matches CLI behavior)
- [x] Hardware RNG (`esp_fill_random`) for AES authenticate nonce

### Card Recovery & Diagnostics
- [x] `try-key` command — test raw AES keys against specific slots
- [x] `scan-keys` command — auto-scan 7 likely candidates in one session
- [x] Auth delay handling: "keep trying" rapid retry within same connection
- [x] Audit logging — all key attempts and writes logged to `/tmp/bolty-audit.log`
- [x] Root cause analysis: M5StickC polling bug identified and fixed
- [x] Empirical NTAG424 auth delay testing (9 tests, all documented)
- [x] `crashlog` command — boot count, reset reason, crash history via NVS

### Platform Support
- [x] PCSC desktop CLI (ACS ACR1252 verified — full burn/wipe/diagnose cycle)
- [x] M5StickC Plus firmware (MFRC522 I2C, ST7789 display, serial console)
- [x] M5Atom Matrix firmware (MFRC522 I2C, LED matrix)
- [x] WiFi + HTTPS REST API (self-signed TLS, bearer token auth, 11 endpoints)
- [x] OTA firmware update (Ed25519 signed — tools/ota-sign.py for keygen/sign)
- [x] PN532 NFC reader support (pn532-transport + bolty-pn532 crates)
- [x] STM32 skeleton (apps/bolty-stm32 — compiles, hardware init pending)
- [x] Button support (GPIO37 front + GPIO39 side, simple + legacy modes)
- [x] Display mode bars + battery indicator (AXP192 voltage reading)
- [x] `hwtest` command — interactive hardware self-test with display feedback
- [x] `button-mode` command — switch between simple and legacy C++ compat
- [x] `token` command — set REST API bearer token via serial
- [x] BLE transport — two approaches available:
  - `main` branch: esp-idf-svc Bluedroid (forked, ai-experimental patch)
  - `esp32-nimble-ble` branch: NimBLE (encrypted, LE Secure Connections)
  - Security: read-only whitelist + opt-in feature (issue #34)

### Fork Management & DRY
- [x] iso14443-rs fork: 6 branches, 6 issues, ai-experiments default
  (PcdSession, WTX timeout, R(ACK) fix, chain recovery, dep pinning)
- [x] mfrc522-rs fork: ai-experiments default, MIT OR Apache-2.0
- [x] ntag424 fork: 4 branches, 4 issues, ai-experiments default
  (Sdm::disabled(), LenCap=0x03 A/B tested on hardware)
- [x] Cross-project DRY: mfrc522-pcd shared by bolty-rs + ccid-firmware-rs
- [x] Cross-project DRY: pn532-transport shared by bolty-rs + ccid-firmware-rs
- [x] All forks documented with LICENSING.md

### Quality & Architecture
- [x] Comprehensive test suite (unit + integration via MockTransport)
- [x] PCD↔PICC loopback tests (5 tests, no hardware required)
- [x] Pre-commit hook: secret scan + fmt + clippy + unit tests
- [x] CI: GitHub Actions (fmt, clippy, test, cargo-audit, cargo-deny)
- [x] Zero warnings on both host and ESP32 builds
- [x] GPL-3.0-or-later license (documented dependency chain)
- [x] Firmware modularization (console_commands → card_operations + diagnostics)
- [x] Polling safety: unauthenticated `poll_safe()` — zero auth APDUs
- [x] Hardware watchdog (TWDT 5s) — auto-reset on I2C hang
- [x] `keys` command marked as advanced with standard reference
- [x] NVS persistence: LNURL + button mode + OTA signing key + TLS cert survive reboots

## In Progress

- [ ] Issue #33: Serial console startup crash on M5StickC (AXP192 I2C init)
- [ ] Issue #34: BLE pairing/bonding (NimBLE branch ready, blocked on hardware)
- [ ] M5StickC UART0 hardware failure — needs replacement device
- [ ] iso14443-rs upstream contribution (waiting for stability proof)

## Planned

### Card Recovery & Diagnostics (Priority: High)
- [x] `try-key` command — test raw AES key against specific slot
- [x] `scan-keys` command — auto-scan 7 likely candidates
- [x] `reset-card` command — clear auth delay via "keep trying"
- [x] `test-ck` command — ChangeKey A/B round-trip verification
- [x] Circuit breaker for repeated authentication failures (#27 closed)
- [x] Auth delay "keep trying" (rapid AuthFirst in same connection)
- [x] `--json` output mode for diagnose
- [ ] `raw-apdu` command — send arbitrary hex APDU for advanced debugging
- [ ] Human-readable SDM config in `diagnose` (offsets explained in plain English)
- [ ] Card fingerprinting — short hash of key state for quick comparison
- [ ] `--json` for try-key, scan-keys, keyver (diagnose done)

### Firmware (Priority: Medium)
- [x] REST API bearer token auth (`token` command)
- [x] REST API TLS (self-signed HTTPS via on-device cert generation)
- [x] OTA signature verification (#31 closed — Ed25519)
- [x] Safety checklist programmatic enforcement (#29 closed — burn/wipe guards)
- [x] `--force` flag to bypass safety checks
- [ ] Standalone LED-only mode — physical switch for mode selection
- [ ] BLE pairing/bonding — NimBLE branch ready, needs hardware test
- [ ] microfips mesh integration (see docs/ble-research.md)

### Ecosystem (Priority: Low)
- [ ] BTCPayServer boltcard plugin compatibility testing
- [ ] LNbits boltcards extension compatibility testing
- [ ] Cross-implementation test vectors (shared fixture format)
- [ ] Card lifecycle management — track card state across sessions

### Polish (Priority: Low)
- [ ] Firmware versioning in REST API responses
- [ ] ESP32 CI workflow (actually build firmware in GitHub Actions)
- [ ] Additional documentation: ADRs, threat model
- [ ] Performance benchmarks for APDU exchange latency
