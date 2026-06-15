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

### Card Recovery
- [x] `try-key` command — test raw AES keys against specific slots
- [x] `scan-keys` command — auto-scan 7 likely candidates in one session
- [x] Auth delay handling with exponential backoff (5s/15s/30s)
- [x] Audit logging — all key attempts and writes logged to `/tmp/bolty-audit.log`
- [x] Root cause analysis: M5StickC polling bug identified and fixed

### Platform Support
- [x] PCSC desktop CLI (ACS ACR1252 verified — full burn/wipe/diagnose cycle)
- [x] M5StickC Plus firmware (MFRC522 I2C, LCD display, serial console)
- [x] M5Atom Matrix firmware (MFRC522 I2C, LED matrix)
- [x] WiFi + REST API (verified — port 80, mDNS `bolty.local`, 7 endpoints)
- [x] OTA firmware update (implemented, no signature verification yet)
- [x] PN532 transport support (in progress — new crates added)

### Quality
- [x] Comprehensive test suite (unit + integration via MockTransport)
- [x] Pre-commit hook: secret scan + fmt + clippy + unit tests
- [x] CI: GitHub Actions (fmt, clippy, test, cargo-audit, cargo-deny)
- [x] Zero warnings on both host and ESP32 builds
- [x] `.gitattributes` for consistent line endings
- [x] GPL-3.0-or-later license

## In Progress

- [ ] PN532 NFC reader support (cross-project transport crate)
- [ ] iso14443 `ai-experiments` branch integration

## Planned

### Card Recovery & Diagnostics (Priority: High)
- [ ] `raw-apdu` command — send arbitrary hex APDU for advanced debugging
- [ ] Human-readable SDM config in `diagnose` (offsets explained in plain English)
- [ ] Card fingerprinting — short hash of key state for quick comparison
- [ ] Multi-issuer key scanning — try keys from multiple issuer sources
- [ ] Circuit breaker for repeated authentication failures (#27)

### Firmware (Priority: Medium)
- [ ] REST API authentication — bearer token or HMAC request signing
- [ ] REST API TLS — switch from HTTP to HTTPS (ESP-IDF `esp_https_server`)
- [ ] Standalone LED-only mode — physical switch for mode selection (identify/wipe/burn)
- [ ] BLE transport research — FFI bindings for ESP-IDF BLE GATT server
- [ ] OTA signature verification (#31)
- [ ] Safety checklist programmatic enforcement (#29)

### Ecosystem (Priority: Medium)
- [ ] BTCPayServer boltcard plugin compatibility testing
- [ ] LNbits boltcards extension compatibility testing
- [ ] Cross-implementation test vectors (shared fixture format)
- [ ] Card lifecycle management — track card state across sessions

### Polish (Priority: Low)
- [ ] Firmware versioning in REST API responses
- [ ] ESP32 CI workflow (actually build firmware in GitHub Actions)
- [ ] Additional documentation: ADRs, threat model
- [ ] Performance benchmarks for APDU exchange latency
