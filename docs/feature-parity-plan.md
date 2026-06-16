# Feature Parity Plan: bolty-rs as C++ Bolty Replacement

Goal: make bolty-rs a **drop-in replacement** for the original C++ Bolty firmware.
Every feature the C++ version has, bolty-rs must have — and do it better.

## Current Parity: 90%+

- **70+** features from C++ Bolty: ✅ DONE
- **6** features: ⬜ MISSING (this plan)
- **15** features: ✅ bolty-rs ADVANTAGES (not in C++)

## Missing Features (in priority order)

### Tier 1: Compatibility Breaking (must have for drop-in replacement)

| # | Feature | C++ Source | Effort | Why It Matters |
|---|---|---|---|---|
| 1 | `testck` command | serial_commands.h | S | C++ users expect it for ChangeKey self-test. Tests: change K1 to test key, re-auth, change back. Our `try-key` covers this but `testck` is the C++ convention. |
| 2 | REST key version endpoint | bolty_rest_server.h | S | Cloudflare Worker e2e tests call `/api/keyver`. Without it, automation breaks. |
| 3 | REST NDEF endpoint | bolty_rest_server.h | S | Cloudflare Worker calls `/api/ndef` to read raw NDEF. Needed for inspect-via-REST. |
| 4 | REST job endpoint | bolty_rest_server.h | M | Async job tracking (burn/wipe progress). C++ returns job status. Needed for REST automation parity. |

### Tier 2: Usability (improves operator experience)

| # | Feature | C++ Source | Effort | Why It Matters |
|---|---|---|---|---|
| 5 | `--force` flag on burn/wipe | N/A (new) | S | Override safety checks for advanced users. Currently burn refuses wrong state. |
| 6 | `dummyburn` command | serial_commands.h | S | Burns NDEF+SDM without changing keys. Useful for testing SDM without key rotation risk. C++ has this as a serial command. |
| 7 | Auto-detect card state on REST | bolty_rest_server.h | S | C++ REST auto-detects card type and reports. We report but don't auto-format. |

### Tier 3: Platform (extends hardware support)

| # | Feature | C++ Source | Effort | Why It Matters |
|---|---|---|---|---|
| 8 | PN532 NFC frontend support | N/A (new) | L | PN532 is the most common DIY NFC reader. Crates exist, transport in progress. |
| 9 | ST25R95 NFC frontend | N/A (new) | L | Foundation Devices uses this. Plan documented in docs/st25r95-plan.md. |
| 10 | STM32 platform support | N/A (new) | L | Skeleton exists (apps/bolty-stm32). Enables non-ESP32 hardware. |

### Out of Scope (backend integration, not firmware)

| # | Feature | Why Out of Scope |
|---|---|---|
| 11 | Web key lookup | Requires backend service integration |
| 12 | WiFi AP mode provisioning | C++ does this; we use WiFi STA only |

## Implementation Plan

### Phase 1: REST API Parity (Day 1)

Goal: Cloudflare Worker e2e tests pass against bolty-rs firmware.

**1.1 REST key version endpoint** (`GET /api/keyver`)
- Call `dispatch_command(Command::KeyVer, ...)` internally
- Return JSON: `{"ok": true, "versions": ["0x01", "0x01", ...]}`
- Effort: **S** (30 min)

**1.2 REST NDEF endpoint** (`GET /api/ndef`)
- Read NDEF file content (256 bytes)
- Return JSON: `{"ok": true, "ndef": "<hex>", "url": "<parsed URL>"}`
- Effort: **S** (30 min)

**1.3 REST job endpoint** (`POST /api/job` + `GET /api/job/<id>`)
- Async burn/wipe with job tracking
- Return job ID, poll for completion
- Effort: **M** (2 hours)

### Phase 2: Serial Command Parity (Day 1)

**2.1 `testck` command**
- Change K1 to test key → re-auth K0 → change K1 back
- Report success/failure per key
- Effort: **S** (30 min)

**2.2 `dummyburn` command**
- Write NDEF + configure SDM without changing keys
- Use existing burn code but skip ChangeKey steps
- Effort: **S** (1 hour)

**2.3 `--force` flag on burn/wipe**
- Add `--force` CLI flag
- When set, skip state check and URL validation
- Print warning: "Safety checks bypassed"
- Effort: **S** (30 min)

### Phase 3: NFC Frontend Expansion (Week 1-2)

**3.1 PN532 transport** (in progress)
- Crates exist: `pn532-transport`, `bolty-pn532`
- Needs: SPI/UART transport, ISO 14443-4 framing
- Effort: **L** (1-2 days)

**3.2 ST25R95 transport** (planned)
- Plan in docs/st25r95-plan.md
- Uses Foundation Devices `st25r95` crate
- Effort: **L** (2-3 days)

**3.3 Unified board config**
- Plan in docs/unified-board-config.md
- Auto-detect NFC frontend at boot
- Effort: **M** (1 day)

### Phase 4: Production Hardening (Week 2-3)

**4.1 OTA signature verification** (#31)
- Ed25519 signature appended to firmware image
- Public key compiled into firmware
- Build script generates signature offline
- Effort: **M** (4 hours)

**4.2 BLE pairing + bonding** (#34)
- Wait for esp-idf-svc 0.53.0 release
- Or fork esp-idf-svc and patch struct mismatch
- BLE read-only whitelist already in place
- Effort: **M** (4 hours after dependency fixed)

**4.3 M5StickC hardware replacement** (#33)
- Replace dead UART0 device
- Flash latest firmware
- Test WiFi + REST + BLE end-to-end
- Effort: **S** (once hardware available)

## Success Criteria

bolty-rs is a drop-in replacement when:

- [ ] Cloudflare Worker e2e tests pass with bolty-rs firmware
- [ ] All C++ serial commands have Rust equivalents
- [ ] REST API endpoints match C++ (keyver, ndef, job)
- [ ] PN532 readers work alongside MFRC522
- [ ] OTA updates are signed
- [ ] No card bricking from normal operation

## Migration Guide (C++ → bolty-rs)

| C++ Command | bolty-rs Equivalent | Notes |
|---|---|---|
| `keys <k0> <k1> <k2> <k3> <k4>` | `keys <k0> <k1> <k2> <k3> <k4>` | Same |
| `burn` | `burn` | Same (adds pre-flight + safety checks) |
| `wipe` | `wipe` | Same (refuses BLANK cards) |
| `uid` | `uid` | Same |
| `inspect` | `inspect` | Same |
| `picc` | `picc` | Same |
| `diagnose` | `diagnose` | Same (better classification) |
| `url` | `url` | Same |
| `status` | `status` | Same |
| `derivekeys` | `derive-keys` | CLI hyphenated |
| `wifi <ssid> <pass>` | `wifi <ssid> <pass>` | Same |
| `resetNdefOnly` | *(use `burn` to re-burn NDEF)* | C++ specific, not needed |
| `testck` | `testck` *(TODO Phase 2)* | Not yet implemented |
| `recoverkey <N> <key>` | `try-key --key <hex> --key-no <N>` | Better: auto auth-delay retry |
| *(no equivalent)* | `scan-keys` | bolty-rs advantage |
| *(no equivalent)* | `reset-card` | bolty-rs advantage |
| *(no equivalent)* | `cycle` | bolty-rs advantage |
| *(no equivalent)* | `token` | bolty-rs advantage |
| `dummyburn` | `dummyburn` *(TODO Phase 2)* | Not yet implemented |
