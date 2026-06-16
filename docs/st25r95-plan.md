# ST25R95 Chip Support Plan

## Chip overview

The ST25R95 is an STMicroelectronics multi-protocol NFC transceiver. Foundation Devices has a production-quality Rust driver (`st25r95` crate, GPLv3, type-state pattern).

| | ST25R95 | MFRC522 | PN532 |
|---|---|---|---|
| **Maker** | STMicroelectronics | NXP | NXP |
| **Type** | Raw transceiver | Raw transceiver | Controller |
| **ISO 14443** | External (needs iso14443-rs) | External (needs iso14443-rs) | Internal |
| **Protocols** | 14443A/B, 15693, FeliCa | 14443A only | 14443A/B |
| **Bus** | SPI | SPI, I2C, UART | SPI, I2C, UART |
| **Card emulation** | Yes (hardware) | No | No |
| **Rust driver** | Foundation-Devices/st25r95 (GPLv3) | Amperstrand/mfrc522-rs fork | crates.io pn532 (MIT) |

## Why consider ST25R95

1. **Multi-protocol**: Supports ISO 14443A/B, ISO 15693, and FeliCa — most versatile chip
2. **Card emulation**: Can act as a card (useful for testing and future features)
3. **Foundation Devices driver**: Type-state pattern, production-quality, actively maintained
4. **Direct register control**: Fine-grained RF optimization (antenna tuning, gain, etc.)
5. **Community**: Well-documented by ST, Arduino libraries available

## Integration plan

### Crate structure (following existing patterns)

```
bolty-rs workspace:
  crates/st25r95-pcd/       ← Shared ST25R95 PcdTransceiver (like mfrc522-pcd)
                               Depends on: st25r95 crate (Foundation Devices), iso14443
  crates/bolty-st25r95/     ← ntag424::Transport impl (like bolty-mfrc522)
                               Depends on: st25r95-pcd, ntag424
```

### Dependencies

```toml
# crates/st25r95-pcd/Cargo.toml
[dependencies]
st25r95 = { git = "https://github.com/Foundation-Devices/st25r95.git" }
iso14443 = { workspace = true }
embedded-hal = "=1.0.0"
log = "=0.4.29"
```

**License note**: st25r95 is GPLv3 — same as iso14443-rs. No new licensing impact on bolty-rs.

### Pin assignments (ESP32, SPI)

| Signal | ESP32 GPIO | ST25R95 Pin | Notes |
|---|---|---|---|
| SCK | GPIO18 | SCK | HSPI clock |
| MISO | GPIO19 | MISO | HSPI MISO |
| MOSI | GPIO23 | MOSI | HSPI MOSI |
| CS | GPIO5 | SSI/CS | Chip select |
| IRQ | GPIO16 | IRQ_OUT | Interrupt (data ready) |
| RST | GPIO17 | NRST | Reset (optional) |
| VCC | 3.3V | VPS | Power |
| GND | GND | GND | Ground |

### Boot detection

ST25R95 would be detected via SPI (not I2C). The detection sequence:
1. If I2C scan doesn't find MFRC522 (0x28) or PN532 (0x24)
2. Try SPI init with ST25R95 driver
3. If `St25r95::new()` succeeds: ST25R95 detected

### Feature flag

```toml
[features]
nfc-st25r95 = ["dep:st25r95-pcd", "dep:bolty-st25r95"]
nfc-auto = ["nfc-mfrc522", "nfc-pn532", "nfc-st25r95"]
```

### PcdTransceiver implementation

The ST25R95 is a raw transceiver like the MFRC522. The st25r95 crate provides `send_receive()` which handles framing. A `St25r95Transceiver` would implement `PcdTransceiver` by:
1. Converting iso14443 `Frame` to ST25R95 raw bytes
2. Calling `nfc.send_receive(&bytes)`
3. Converting response back to `FrameVec`

This is the same pattern as `Mfrc522Transceiver` but for a different chip.

### Type-state pattern adoption

Foundation Devices' st25r95 driver uses 5 type-state parameters. The bolty-rs integration would:
1. Use the driver in `Reader` + `Iso14443A` + `FieldOn` state
2. Keep the state transitions inside `activate()`
3. Expose a simplified API that matches our `PcdTransceiver` trait

### Implementation phases

1. **Phase 1**: Create `st25r95-pcd` crate stub (Cargo.toml + lib.rs with PcdTransceiver impl)
2. **Phase 2**: Create `bolty-st25r95` crate (Transport impl)
3. **Phase 3**: Add `nfc-st25r95` feature to bolty-esp32
4. **Phase 4**: Hardware test with ST25R95 module

### Hardware needed

- ST25R95 breakout board or evaluation kit (e.g., X-NUCLEO-NFC03A1)
- SPI wiring to ESP32
- Antenna (typically comes with the breakout board)

### Status

Planning only. No hardware available yet. Crate stubs can be created when we're ready to start implementation. The Foundation Devices driver is actively maintained (last commit May 2026) and the type-state pattern is well-documented.
