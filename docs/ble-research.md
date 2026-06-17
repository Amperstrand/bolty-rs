# BLE Transport Research & Decision

## Problem

The M5StickC Plus UART0 is dead (hardware failure from USB power cycling
experiments). Serial console no longer works. We need an alternative
wireless transport to communicate with the device.

## Option Evaluation

### Option A: Fork esp-idf-svc (CURRENT — fastest path)

**Status**: Forked, patched, wired into bolty-rs. Awaiting hardware rebuild.

Fork: `Amperstrand/esp-idf-svc` branch `ai-experimental/fix-ble-ping-en`
Patch: 2 lines commented out (`ble_ping_en` struct field removed in ESP-IDF 5.2+)

| Aspect | Rating | Notes |
|---|---|---|
| Implementation effort | ✅ Minimal | 2-line patch, existing `ble.rs` code ready |
| Risk to WiFi/REST | ⚠️ Low | `[patch.crates-io]` only affects builds with `ble` feature |
| BLE auth | ⚠️ Mitigated | Read-only whitelist (no burn/wipe via BLE) |
| BLE encryption | ❌ None | Unencrypted BLE link |
| Mesh networking | ❌ None | Point-to-point only |
| Maintenance | ⚠️ Fork burden | Delete patch when esp-idf-svc 0.53.0 releases |

**Decision**: Use this approach for immediate BLE access. Remove when
esp-idf-svc releases a fix.

### Option B: Rewrite with esp32-nimble crate

Replace esp-idf-svc BLE with the community `esp32-nimble` crate.

| Aspect | Rating | Notes |
|---|---|---|
| Implementation effort | ❌ Large | Complete rewrite of `ble.rs` (280 lines) |
| Risk to WiFi/REST | ✅ None | NimBLE doesn't touch esp-idf-svc WiFi/REST code |
| BLE auth | ✅ Built-in | NimBLE supports pairing/bonding natively |
| BLE encryption | ✅ Yes | NimBLE stack handles encryption |
| RAM usage | ✅ Lower | NimBLE is lighter than Bluedroid (~30% less RAM) |
| Maintenance | ✅ Community | Actively maintained, no fork needed |
| Mesh networking | ❌ None | Still point-to-point |

**Decision**: Evaluate after Option A proves the concept. If BLE works
well and we want pairing/bonding, migrate to esp32-nimble.

### Option C: microfips integration (STRATEGIC — future direction)

Integrate with the microfips project (`../microfips`) to use the FIPS
mesh networking protocol as a transport layer.

**microfips overview**: A Rust embedded firmware implementing leaf
FIPS (Free Internetworking Peering System) nodes with:
- Noise_IK/XK handshakes (end-to-end encryption, no pairing needed)
- FMP link framing + FSP session protocol
- BLE GATT, BLE L2CAP, WiFi, and serial transports (all verified on ESP32)
- Transport-neutral service layer for application request/response

| Aspect | Rating | Notes |
|---|---|---|
| Implementation effort | ❌ Very large | Architecture mismatch (esp-hal vs esp-idf-svc) |
| Risk to WiFi/REST | ❌ High | May require firmware rewrite |
| Auth | ✅ Excellent | Noise_IK handshake = crypto-grade auth by design |
| Encryption | ✅ Excellent | All traffic encrypted (Noise protocol) |
| Mesh networking | ✅ Yes | Multi-hop relay between FIPS nodes |
| BLE library | ✅ No conflict | microfips uses esp-hal + esp32-nimble (not esp-idf-svc) |
| Code reuse | ✅ Potential | `microfips-service` provides transport-neutral API |

**Architecture challenge**: bolty-rs uses `esp-idf-svc` (std-based),
microfips uses `esp-hal` (no_std). Two possible integration paths:

1. **microfips as firmware, bolty-rs as service**: M5StickC runs
   microfips firmware. NFC card operations exposed through
   `microfips-service` layer. Commands relayed over FIPS mesh.
   bolty-rs CLI on PC talks to the mesh node.

2. **Separate devices**: bolty-rs on PC/ACS reader handles card ops.
   microfips on a separate ESP32 handles mesh networking. The two
   communicate via serial or HTTP.

**Decision**: Long-term strategic direction. Not for immediate
implementation. Revisit after Option A validates BLE usefulness.

## Comparison Summary

| Feature | Fork+patch (A) | esp32-nimble (B) | microfips (C) |
|---|---|---|---|
| Effort | 2 lines | ~300 lines rewrite | Architecture change |
| Time to working | Hours | Days | Weeks |
| Encryption | ❌ | ✅ (pairing) | ✅ (Noise_IK) |
| Auth | Read-only whitelist | BLE pairing | Crypto handshake |
| Mesh | ❌ | ❌ | ✅ |
| Library conflict | ❌ (patch fixes it) | ❌ (different stack) | ❌ (different framework) |
| Production ready | ⚠️ Temporary fork | ✅ Stable crate | ✅ Proven on hardware |

## Decision Matrix

| Scenario | Recommended Path |
|---|---|
| Need BLE NOW (UART dead) | **Option A** (fork+patch) |
| Want BLE with encryption | **Option B** (esp32-nimble) |
| Want mesh networking | **Option C** (microfips) |
| PCSC CLI is sufficient | None needed (current state) |

## References

- esp-idf-svc fork: https://github.com/Amperstrand/esp-idf-svc/tree/ai-experimental/fix-ble-ping-en
- esp32-nimble crate: https://crates.io/crates/esp32-nimble
- microfips project: https://github.com/Amperstrand/microfips (local: `../microfips`)
- esp-idf-svc master changelog: https://github.com/esp-rs/esp-idf-svc/blob/master/CHANGELOG.md
- NimBLE vs Bluedroid comparison: https://medium.com/@zeni241/nimble-with-esp32-for-dummies-6946613136b7
