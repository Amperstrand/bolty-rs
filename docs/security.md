# Security Model

## Threat Model

Bolty-rs is a Bolt Card programmer that handles cryptographic key material
(AES-128 keys for NTAG424 DNA cards) and can modify payment routing URLs
on cards. An attacker who gains access to the device can:

1. **Redirect payments**: Burn a card with attacker-controlled URL →
   Lightning payments go to attacker's server
2. **Brick cards**: Repeated wipe/burn exhausts TotFailCtr (1000 failures =
   permanent key lock)
3. **Steal keys**: Read issuer key or card keys from device memory
4. **Firmware tampering**: Replace firmware via OTA with malicious code

## Transport Security Matrix

| Transport | Authentication | Encryption | Attack Range | Risk Level |
|---|---|---|---|---|
| **Serial (UART)** | Physical access required | None (but physical) | Touch device | Low |
| **WiFi REST** | Bearer token (read + write scopes) | TLS 1.2 (per-device cert) | WiFi range (~30m) | Low |
| **BLE (current)** | **NONE** | **NONE** | BLE range (~30m) | **CRITICAL** |
| **BLE (read-only)** | N/A (no writes) | None | BLE range (~30m) | Low |
| **OTA** | **None** (no signature) | HTTPS URL only | Network | **HIGH** |

## Current Security Measures

### Key Storage (GOOD)
- All AES keys (K0-K4, issuer key) stored in **RAM only**
- `AesKey` implements `Drop` with `zeroize()` — wiped on scope exit
- `Debug` trait redacts key values (`[REDACTED]`)
- Keys are **never** persisted to NVS or flash
- Only LNURL and button mode are persisted to NVS

### Card Operations (GOOD)
- Burn derives keys from issuer key via `BoltcardDeterministicDeriver`
- `keys` command marked as advanced with standard reference
- Auth probe tries factory K0 first, then derived K0 (supports re-burn)
- Wipe requires authenticated K0 access
- `poll_safe()` never authenticates (zero SeqFailCtr risk)

### Serial Console (ACCEPTABLE)
- No authentication — relies on physical access
- DTR/RTS reset sequence can reboot device
- All commands available (including burn, wipe, keys)

### WiFi REST API (GOOD — cable-pairing TLS)
- HTTPS with per-device self-signed certificate (RSA-2048, SHA-256)
- Certificate generated on-device via mbedTLS — private key never leaves ESP32
- `provision-cert` serial command generates + stores cert in NVS
- REST server refuses to start until cert is provisioned
- SHA-256 fingerprint printed to serial for client-side pinning (TOFU)
- Bearer token authentication with separate read/write scopes
- `token` serial command sets/clears REST tokens
- `constant_time_eq()` prevents timing attacks on token comparison
- mDNS advertises device as `bolty.local`

### BLE Transport (CRITICAL — Issue #34)
- **No authentication**: any BLE client can connect
- **No encryption**: commands visible to eavesdroppers
- **No command filtering** (being fixed): burn, wipe, keys all exposed
- **Read-only mode** (implemented): BLE restricted to status/uid/inspect/diagnose
- **Opt-in** (implemented): `ble` feature must be explicitly enabled

### OTA Updates (HIGH — Issue #31)
- Downloads firmware from arbitrary URL
- **No signature verification**: attacker on network path can inject firmware
- **No checksum validation**: corrupted firmware bricks device
- Uses HTTPS if URL is https:// (but no cert pinning)

## Security Fixes (Implemented)

### BLE Read-Only (Option C) — DONE
`process_ble_command()` now whitelists only safe commands:
- **Allowed**: Status, Uid, Inspect, Diagnose, Picc, Check
- **Blocked**: Burn, Wipe, SetKeys, SetIssuer, SetUrl, SetToken
Response: `[FAIL] write commands blocked via BLE (issue #34)`

### BLE Opt-In (Option D) — DONE
`ble` feature is NOT in any board's default features. Must be explicitly
enabled: `--features "board-m5stick,ble"`
Cargo.toml includes security warning comment.

### HTTPS with Cable-Pairing Cert — DONE
Removed the shared development certificate from the firmware binary.
Each device now generates its own RSA-2048 self-signed certificate on
first boot via mbedTLS FFI:

1. User connects via USB serial, sends `provision-cert`
2. Device generates RSA-2048 keypair using hardware RNG (entropy → CTR_DRBG)
3. Device creates self-signed X.509 v3 cert (CN=bolty, SHA-256, 10-year validity)
4. Cert + key DER blobs stored in NVS
5. SHA-256 fingerprint printed to serial console
6. REST API refuses to start until cert exists (`ESP_ERR_INVALID_STATE`)
7. User pins fingerprint in client (trust-on-first-use model)

The private key is generated entirely on-device and never transits any cable.
Boot diagnostics print `hw: cert=provisioned` or `hw: cert=NOT_PROVISIONED`.

## Security Plan

### Priority 1: BLE Pairing + Bonding (Option A)
**Issue**: #34
**Goal**: Require PIN entry before BLE commands
**Approach**: ESP-IDF BLE security manager with passkey pairing
**Effort**: Medium (ESP-IDF BLE security API is complex in Rust)

```c
// C API approach (needs Rust binding):
esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, ...);
// Set CMD characteristic permission to Authenticated
```

### ~~Priority 2: HTTPS for REST API~~ — DONE
See "HTTPS with Cable-Pairing Cert" in Security Fixes above.

### Priority 3: OTA Signature Verification
**Issue**: #31
**Goal**: Reject unsigned firmware updates
**Approach**: Ed25519 signature appended to firmware image
**Details**: Firmware image = binary + 64-byte signature
**Verification**: Embedded public key verifies signature before flashing
**Tooling**: Build script generates signature with private key (offline)

### Priority 4: Rate Limiting
**Goal**: Prevent brute-force on auth tokens and BLE spam
**Approach**: Exponential backoff after N failed auth attempts
**Applies to**: REST token failures, BLE command frequency

## Comparison with Original C++ Bolty

The original C++ Bolty ([bitcoin-ring/Bolty](https://github.com/bitcoin-ring/Bolty), commit `9c4da96`) has an explicitly weak security model. The author's own README states:

> *"currently not so much, so be careful"*

### C++ Bolty Security Model

| Aspect | C++ Bolty | bolty-rs | Improvement |
|---|---|---|---|
| **WiFi protocol** | HTTP only (port 80) | HTTPS (per-device TLS cert) | ✅ bolty-rs encrypts all REST traffic |
| **Auth on burn/wipe** | **NONE** — unprotected | Bearer token required | ✅ bolty-rs secures ALL endpoints |
| **Auth on setup** | Basic Auth (default: bolty/bolty) | Bearer token (user-configurable) | ✅ No default credentials |
| **Key storage** | **Plain text** on SPIFFS | **RAM only**, zeroized on drop | ✅ Keys never persisted |
| **Serial key dumps** | Yes — `dumpconfig()` prints K0-K4 | No — Debug trait redacts | ✅ No key leakage |
| **BLE** | Not implemented | Read-only whitelist (opt-in) | bolty-rs has BLE with security |
| **OTA** | Not implemented | HTTPS download (no sig yet) | bolty-rs has OTA (needs signing) |
| **Backup encryption** | Unencrypted binary dump | N/A (no backup feature) | — |

### What C++ Bolty gets right (that we should match)
- Physical button access (no PIN needed for trusted local operation)
- WiFi AP mode with random password for initial setup

### What bolty-rs already does better
- Token auth on ALL REST endpoints (C++ only protects setup pages)
- Keys in RAM only (C++ stores plain text on flash)
- No serial key dumps (C++ prints all keys to console)
- BLE read-only whitelist (C++ has no BLE)
- Constant-time token comparison (C++ uses plaintext strcmp)

## Security Audit Checklist

- [x] Key material zeroized on drop
- [x] Debug trait redacts secrets
- [x] Keys never persisted to flash
- [x] REST API has bearer token auth
- [x] REST token comparison is constant-time
- [x] `keys` command marked as advanced
- [x] BLE restricted to read-only commands
- [x] BLE is opt-in feature
- [x] `poll_safe()` never authenticates (card safety)
- [x] Hardware watchdog prevents hangs
- [x] I2C timeout prevents bus lockup
- [x] Crash diagnostics (boot count + reset reason in NVS)
- [ ] BLE pairing + bonding (Option A)
- [x] HTTPS for REST API (cable-pairing TLS cert)
- [ ] OTA signature verification
- [ ] Rate limiting on auth endpoints
- [ ] Audit log for BLE commands
