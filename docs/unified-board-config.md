# Unified Board Configuration Design

## Goal

Auto-detect NFC frontend (MFRC522 or PN532) at boot, making both chips first-class citizens without requiring separate firmware builds per chip.

## Current architecture

```
Board features define I2C pins → I2C scan → MFRC522 at 0x28?
  ├─ Yes: Mfrc522Transceiver<I2C> → Esp32BoltyService<I2C>
  └─ No:  raw_i2c retained, nfc_ready=false

Esp32BoltyService<I2C: I2c> {
    transceiver: Option<Mfrc522Transceiver<I2C>>,  // hardcoded to MFRC522
    ...
}
```

**Problem**: Service is parameterized by `I2C: I2c` and hardcoded to `Mfrc522Transceiver`. Adding PN532 requires either:
- A separate service struct (code duplication)
- A generic service that abstracts over the NFC backend (preferred)

## Proposed architecture

### NFC backend enum

```rust
pub enum NfcBackend {
    Mfrc522(Mfrc522Transceiver<esp_idf_hal::i2c::I2cDriver>),
    Pn532(Pn532Device<Pn532<...>, GpioPin>),
    None,
}
```

The service holds `NfcBackend` instead of `Option<Mfrc522Transceiver<I2C>>`. Each variant provides the same operations: activate transport, poll for cards, exchange APDUs.

### Trait-based alternative (more flexible)

```rust
pub trait NfcFrontend {
    fn activate(&mut self) -> Result<Box<dyn ntag424::Transport>, NfcError>;
    fn card_present(&mut self) -> bool;
    fn poll_safe(&mut self) -> Option<CardAssessment>;
}
```

Each backend implements this trait. The service holds `Box<dyn NfcFrontend>`.

**Tradeoff**: Enum is zero-cost and simpler. Trait object needs `alloc` (already available) but allows future backends (ST25R95) without modifying the enum.

**Recommendation**: Start with enum, migrate to trait if we add ST25R95.

### Boot detection sequence

```
1. Init I2C bus
2. Scan I2C addresses:
   ├─ 0x28 found → MFRC522 detected on I2C
   │   → Create Mfrc522Transceiver from I2C
   │   → NfcBackend::Mfrc522
   ├─ 0x24 (PN532 I2C addr) found → PN532 detected on I2C
   │   → Create Pn532Device from I2C + IRQ + RST pins
   │   → NfcBackend::Pn532
   └─ Neither found → Check SPI (if enabled)
       → Try PN532 GetFirmwareVersion on SPI
       → If OK: NfcBackend::Pn532
       → If fail: NfcBackend::None
3. Boot banner: "nfc=mfrc522" or "nfc=pn532" or "nfc=none"
```

### Feature flags

```toml
[features]
# Board defines pin mapping (I2C, SPI, display, LEDs)
board-m5stick = []    # I2C on G32/G33, ST7789 display, AXP192
board-m5atom = []     # I2C on G26/G32, LED matrix
board-generic = []    # User-defined pins via serial config

# NFC frontends (can be enabled together for auto-detect)
nfc-mfrc522 = ["dep:mfrc522-pcd", "dep:bolty-mfrc522"]
nfc-pn532 = ["dep:pn532-transport", "dep:bolty-pn532"]
nfc-auto = ["nfc-mfrc522", "nfc-pn532"]  # Enable both, detect at boot

# Default: MFRC522 only (backward compat)
default = ["board-m5stick", "nfc-mfrc522"]
```

### Pin assignments

Both chips can share I2C bus (different addresses):

| Chip | I2C Address | Bus | Notes |
|---|---|---|---|
| MFRC522 | 0x28 | I2C0 | Grove port on M5StickC/M5Atom |
| PN532 | 0x24 (default) or 0x48 | I2C0 | Configurable via PN532 DIP switches |

For SPI (PN532 only):
| Signal | GPIO | Notes |
|---|---|---|
| SCK | GPIO18 | HSPI clock |
| MISO | GPIO19 | HSPI MISO |
| MOSI | GPIO23 | HSPI MOSI |
| CS | GPIO5 | Chip select |
| IRQ | GPIO16 | Interrupt |
| RST | GPIO17 | Reset |

### Service layer changes

The service needs to abstract over the transport type. The cleanest approach:

```rust
pub struct Esp32BoltyService {
    backend: NfcBackend,
    raw_i2c: Option<I2cDriver>,
    // ... rest unchanged
}

impl Esp32BoltyService {
    fn activate_transport(&mut self) -> Result<NfcTransport, WorkflowResult> {
        match &mut self.backend {
            NfcBackend::Mfrc522(xcvr) => {
                let transport = Mfrc522Transport::activate(xcvr)?;
                Ok(NfcTransport::Mfrc522(transport))
            }
            NfcBackend::Pn532(device) => {
                let mut transport = Pn532Transport::new(device);
                transport.activate()?;
                Ok(NfcTransport::Pn532(transport))
            }
            NfcBackend::None => Err(WorkflowResult::CardNotPresent),
        }
    }
}

pub enum NfcTransport {
    Mfrc522(Mfrc522Transport<'_, I2cDriver>),
    Pn532(Pn532Transport<Pn532<...>, GpioPin>),
}
```

Each variant implements `ntag424::Transport` — burn/wipe/diagnose code works unchanged because it's generic over `T: Transport`.

### Implementation phases

1. **Phase 1**: Add `nfc-pn532` feature flag and `NfcBackend` enum to firmware (no auto-detect yet, compile-time selection)
2. **Phase 2**: Add I2C boot detection (scan for both 0x28 and 0x24)
3. **Phase 3**: Add SPI detection fallback for PN532
4. **Phase 4**: Unified board config with `board-generic` (user-configurable pins via serial)
