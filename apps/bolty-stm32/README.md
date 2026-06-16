# bolty-stm32

Bolt Card firmware for STM32 + MFRC522 (bare-metal `no_std`).

## Status: SKELETON

Compiles for host (type checking) and ARM Cortex-M target. Hardware
initialization is not yet implemented — see TODO in `src/main.rs`.

## Architecture

Same core crates as ESP32 firmware:

```
bolty-stm32 (STM32 firmware)
  ├── Uses: bolty-core, bolty-ntag, bolty-mfrc522 (SAME crates!)
  ├── HAL: stm32f4xx-hal (replaces esp-idf-hal)
  ├── NFC: MFRC522 over I2C (same wiring as ESP32)
  └── Console: UART (replaces USB-UART)
```

The key insight: `embedded-hal::i2c::I2c` is implemented by BOTH
`esp-idf-hal` AND `stm32f4xx-hal`. The `Mfrc522Transceiver<I2C>` works
identically on both platforms.

## Hardware

- **MCU**: STM32F469NI (ARM Cortex-M4F, 180MHz, 2MB flash, 256KB RAM)
- **NFC**: MFRC522 over I2C (same module as ESP32 setup)
- **Console**: UART (PA9 TX, PA10 RX, 115200 baud)
- **Board**: STM32F469-DISCO (same board as ccid-firmware-rs)

## Build

```bash
# Host check (type-checking only)
cargo build -p bolty-stm32

# STM32F469 target (requires thumbv7em-none-eabihf toolchain)
rustup target add thumbv7em-none-eabihf
cargo build -p bolty-stm32 --target thumbv7em-none-eabihf --features board-stm32f4-disco
```

## Flash

```bash
# Using probe-rs (recommended)
probe-rs run --chip STM32F469NI target/thumbv7em-none-eabihf/release/bolty-stm32

# Using OpenOCD + GDB
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg
arm-none-eabi-gdb target/thumbv7em-none-eabihf/release/bolty-stm32
```

## Implementation TODO

1. Initialize STM32 clocks (RCC — 180MHz sysclk)
2. Initialize I2C1 peripheral (PB8 SCL, PB9 SDA, 100kHz)
3. Initialize USART1 (PA9 TX, PA10 RX, 115200 baud)
4. Create `Mfrc522Transceiver::from_i2c(i2c, 0x28)`
5. Port serial console from ESP32 (use UART instead of fd 0/1)
6. Port command parser from ESP32
7. Port `poll_safe()` (unauthenticated card detection)
8. Port burn/wipe/inspect workflows
9. Add GPIO button support (optional)
10. Add display support (optional — STM32F469-DISCO has LCD)
