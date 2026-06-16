# Licensing

## License

This crate is dual-licensed under **MIT OR Apache-2.0**, matching the upstream
`mfrc522` crate from which it is forked.

## Why MIT OR Apache-2.0?

The upstream [mfrc522 crate](https://crates.io/crates/mfrc522) (v0.8.0) uses
the standard Rust dual-license (MIT OR Apache-2.0). As a derivative work, this
fork maintains the same license.

This license is compatible with all downstream consumers:
- **bolty-rs** (GPL-3.0-or-later) — GPL-3.0 can incorporate MIT code
- **ccid-firmware-rs** (GPL-2.0-or-later) — GPL-2.0 can incorporate MIT code

## Relationship to upstream

This fork adds:
- I2C communication support (upstream only supported SPI)
- Hardware timer configuration (`set_timeout_ms` pattern)
- Register access patches for ESP32 I2C bus timing

The upstream crate was at v0.8.0 when forked. This fork is maintained
separately and is not intended for crates.io publication.

## SPDX

`SPDX-License-Identifier: MIT OR Apache-2.0`
