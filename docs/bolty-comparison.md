# Bolty C++ vs bolty-rs: Feature Comparison & Porting Guide

Living document tracking feature parity, architectural differences, and porting priorities.

## Architecture Overview

| Aspect | Bolty C++ | bolty-rs |
|---|---|---|
| **Language** | Arduino C++ (PlatformIO) | Rust (esp-idf-sys, no_std core) |
| **Target** | ESP32 (M5StickC Plus, M5Atom) | ESP32 (M5StickC Plus, M5Atom) |
| **NFC Transport** | MFRC522 I2C (custom library) | MFRC522 I2C (bolty-mfrc522 crate) |
| **NTAG424 Protocol** | Custom MFRC522_NTAG424DNA library | ntag424 crate (v0.1.0-beta1, external) |
| **Crypto** | AES-128 ECB/CBC/CMAC (custom) | ntag424 crate crypto + aes/cmac crates |
| **Key Derivation** | Custom KeyDerivation.h | ntag424 crate key_diversification + bolty-core |
| **Serial** | Arduino Serial (blocking) | esp-idf UART (blocking) |
| **WiFi** | Arduino WiFi (blocking) | esp-idf-svc WiFi |
| **REST API** | Custom AsyncWebSocketServer | esp-idf-svc httpd |
| **OTA** | Custom (TAR+GZ) | esp-idf-svc ota |
| **Display** | — (headless) | ST7789 (mipidsi, optional) |
| **Build** | `pio run -t upload` | `cargo +esp build --release` |
| **Tests** | 349 hardware E2E tests | Unit tests only (no hardware E2E yet) |

## Serial Command Parity

| Command | Bolty C++ | bolty-rs | Notes |
|---|---|---|---|
| `help` | ✅ Full | ✅ Basic | C++ has detailed descriptions per command |
| `status` | ✅ WiFi + NFC + keys | ✅ WiFi + NFC + keys | |
| `uid` | ✅ | ✅ | |
| `keys <k0..k4>` | ✅ | ✅ | Load keys into working memory |
| `issuer [hex]` | ✅ | ✅ | Set issuer key for derivation |
| `url <lnurl>` | ✅ | ✅ | Set LNURL for burn |
| `burn` | ✅ Full | ✅ Full | Rust burn() has auth key bug (hardcoded FACTORY_KEY) |
| `wipe` | ✅ Full | ✅ Full | Rust wipe() has ApduBodyTooLarge fix (untested) |
| `inspect` | ✅ Full read-only | ⚠️ Auth-based only | C++ reads key versions, NDEF, SDM, matches keys offline. Rust requires auth. |
| `check` | ✅ | ✅ | |
| `picc` | ✅ Safe SDM decrypt | ❌ Missing | Reads NDEF, decrypts p= with K1, verifies c= with K2 — NO auth needed |
| `diagnose` | ✅ State classifier | ❌ Missing | BLANK/PROVISIONED/HALF-WIPED/INCONSISTENT/AUTH_DELAY |
| `recoverkey` | ✅ | ❌ Missing | Recover individual key slots using ChangeKey |
| `testck` | ✅ | ❌ Missing | ChangeKey round-trip self-test |
| `derivekeys` | ✅ | ❌ Missing | Derive keys from issuer and show |
| `keyver` | ✅ | ❌ Missing | Read single key version |
| `dummyburn` | ✅ | ❌ Missing | SDM+NDEF write without key change |
| `reset` | ✅ | ❌ Missing | Reset NDEF+SDM on factory-key card |
| `auth` | ✅ | ❌ Missing | Manual auth test |
| `ver` | ✅ | ❌ Missing | GetVersion card type check |
| `wifi <ssid> <pass>` | ✅ | ✅ | |

## SDM / PICC Data Handling

| Feature | Bolty C++ | bolty-rs | Priority |
|---|---|---|---|
| PICC p= decryption (AES-128-CBC, K1) | ✅ PiccData.h | ✅ ntag424 crate (Verifier) | — |
| CMAC c= verification (AES-CMAC, K2) | ✅ PiccData.h | ✅ ntag424 crate (Verifier) | — |
| SV2 derivation vector build | ✅ PiccData.h | ✅ ntag424 crate | — |
| URL p=/c= extraction | ✅ PiccData.h | ✅ ntag424 crate hex module | — |
| Deterministic K1 read-only decrypt | ✅ card_key_matching.h | ✅ bolty-core | — |
| Deterministic K2 CMAC verify | ✅ card_key_matching.h | ✅ bolty-core | — |
| Full read-only card assessment | ✅ card_assessment.h | ✅ bolty-core | — |
| Hardcoded issuer key catalog (7 keys) | ✅ card_key_matching.h | ✅ bolty-core | — |
| Version candidate probing (0,1,2,3) | ✅ card_key_matching.h | ✅ bolty-core | — |
| **Wired into serial commands** | ✅ `picc`, `inspect` | ❌ Not wired yet | **HIGH** |
| Web key lookup | ✅ card_web_lookup.h | ❌ Missing | Medium |

## Auth Delay (0x91AD) Handling

| Feature | Bolty C++ | bolty-rs | Priority |
|---|---|---|---|
| Error code parsing (SW2_AUTH_DELAY) | ✅ bolty_utils.h | ✅ ntag424 ResponseStatus::AuthenticationDelay | — |
| diagnose detects AUTH_DELAY state | ⚠️ Being added | ❌ No diagnose command | HIGH |
| Auth-safety warnings before burn/wipe | ⚠️ Being added | ❌ No warnings | HIGH |
| Safe inspect (no auth needed) | ✅ inspect command | ❌ Inspect requires auth | HIGH |
| recoverkey for locked keys | ✅ recoverkey command | ❌ Missing | Medium |
| TotFailCtr retry guidance | ⚠️ Being added | ❌ Missing | Medium |

## Key Architectural Differences

### 1. NTAG424 Protocol Library

**C++**: Custom `MFRC522_NTAG424DNA` library bundled in lib/. All NTAG424 operations are methods on the NFC reader object. Response parsing is manual.

**Rust**: External `ntag424` crate (v0.1.0-beta1). Type-state pattern — `Session<Unauthenticated>` vs `Session<Authenticated<AesSuite>>`. Compile-time safety for auth state. The crate already has SDM Verifier, PICC data decryption, and key diversification.

**Impact**: The Rust approach is safer but requires adapting the workflow to the type-state pattern. The ntag424 crate's `Verifier` can do everything the C++ `PiccData.h` does.

### 2. Card Assessment

**C++**: `card_assessment.h` does a full multi-phase read-only assessment:
1. Detect card type (GetVersion)
2. Read key versions (PLAIN, no auth)
3. Test zero-key auth on K0 (only if all versions are factory)
4. Read NDEF content
5. Try current issuer key against SDM data (offline)
6. Try web key lookup
7. Try all hardcoded issuer keys
8. Classify: BLANK / PROGRAMMED / UNKNOWN

**Rust**: `bolty-core` has the assessment logic ported, but `bolty-esp32` main.rs only does auth-based inspection. The read-only assessment is not wired into serial commands.

### 3. Burn/Wipe Safety

**C++**: 
- `burn()` checks if key 1 is still factory before burning
- `wipe()` calls `verify_all_keys()` first (probes K3=K1, K4=K2, zero fallback)
- `changeAllKeys()` goes in reverse order (4→3→2→1→0) and aborts on first failure

**Rust**: 
- `burn()` hardcodes FACTORY_KEY for auth ← **BUG** (being fixed)
- `wipe()` takes keys as parameter, uses them correctly
- ChangeKey order is correct (4→3→2→1→0)

### 4. NFC Transport

**C++**: MFRC522 library wraps I2C communication. Soft-reset between activations. 400kHz I2C.

**Rust**: `bolty-mfrc522` crate. Same MFRC522 chip, same I2C speed (400kHz). Proven working on both M5StickC Plus and M5Atom.

## Porting Priorities

### Immediate (unblock card recovery)
1. Fix `burn()` auth key parameterization
2. Add auth delay handling (detect, report, guide)
3. Wire up read-only inspect (no auth)

### Short-term (close safety gap)
4. Wire up ntag424 `Verifier` into serial `picc` command
5. Add `diagnose` command to bolty-rs
6. Add `recoverkey` command to bolty-rs

### Medium-term (full parity)
7. Web key lookup
8. `testck` self-test
9. `dummyburn`, `reset`, `derivekeys` commands
10. Hardware E2E test suite

## SDM Key Verification: How It Works

The most important safety feature: **verifying key ownership without Authenticate**.

### Flow (both C++ and Rust ntag424 crate support this)
1. **Read NDEF** — no auth needed if file settings allow plain read (SDM-enabled cards)
2. **Extract URL** — contains `p=<32-hex-chars>&c=<16-hex-chars>`
3. **Decrypt p=** — AES-128-CBC with K1 (encryption key), zero IV → get UID + read counter
4. **Verify UID match** — decrypted UID must match card's actual UID
5. **Verify c=** — derive session key via SV2 (AES-CMAC of K2 with UID+counter), compute CMAC of empty data, compare odd bytes with c= parameter
6. **Result** — if both pass, we KNOW K1 and K2 are correct, proving we own the card

### Why This Is Safe
- Zero Authenticate APDU commands sent
- Zero risk of incrementing TotFailCtr
- Can be repeated unlimited times without card damage
- Works even when card is in AUTHENTICATION_DELAY state (NDEF read is not auth)

### Keys Confirmed by This Process
- K1 confirmed by p= decryption (format byte + UID match)
- K2 confirmed by c= CMAC verification
- K0, K3, K4 are NOT directly confirmed but are derived from the same issuer key

## Card State Classification Reference

| State | Key Versions | Zero-Key Auth | Description |
|---|---|---|---|
| BLANK | All 0x00 | OK | Factory fresh, ready for burn |
| PROVISIONED | Some non-zero | N/A | Card is locked, needs known keys |
| HALF-WIPED | Some 0x00, some non-zero | OK (K0=0x00) | Partial wipe, recoverable |
| AUTH_DELAY | All 0x00 | FAILED | TotFailCtr triggered, wait and retry |
| INCONSISTENT | Mixed/unknown | FAILED | Card corruption or wrong card type |

## Files Reference

### Bolty C++
- `src/serial_commands.h` — All serial command handlers
- `src/bolt.h` — Core NFC operations (auth, burn, wipe, verify)
- `src/bolty_utils.h` — APDU status parsing, hex helpers
- `src/PiccData.h` — SDM PICC data decryption + CMAC verification
- `src/card_key_matching.h` — Deterministic key derivation + matching
- `src/card_assessment.h` — Full read-only card assessment
- `src/card_web_lookup.h` — Web key server lookup
- `src/KeyDerivation.h` — Key derivation primitives

### bolty-rs
- `crates/bolty-ntag/src/lib.rs` — burn(), wipe(), check_key_versions()
- `crates/bolty-core/` — Key derivation, PICC data, card assessment (ported from C++)
- `crates/bolty-mfrc522/src/lib.rs` — MFRC522 I2C transport
- `apps/bolty-esp32/src/main.rs` — Serial commands, workflow handlers
- `apps/bolty-esp32/src/display.rs` — ST7789 display driver (M5StickC Plus)
- `apps/bolty-esp32/src/rest.rs` — REST API server
- External: `ntag424` crate — Session, Transport, Verifier, SDM, crypto
