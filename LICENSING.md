# Licensing

## License

bolty-rs is licensed under **GPL-3.0-or-later**.

## Why GPL-3.0?

This license is required because bolty-rs depends on `iso14443-rs`
(Foundation-Devices/iso14443-rs, forked at Amperstrand/iso14443-rs), which is
licensed under GPL-3.0-or-later.

Rust crates are statically compiled into the final binary. Static linking with
GPL-3.0 code requires the combined work to also be GPL-3.0-or-later. There is
no LGPL or dynamic-link exception in the iso14443-rs license.

The dependency chain:

```
Foundation-Devices/iso14443-rs    GPL-3.0-or-later
  └─ Amperstrand/iso14443-rs      GPL-3.0-or-later (derivative work)
      └─ bolty-rs                 GPL-3.0-or-later (forced by static linking)
```

## What this means

- **Commercial use**: Allowed, but source code must be provided to recipients.
- **Modification**: Allowed, derivatives must also be GPL-3.0-or-later.
- **Distribution**: Allowed, with complete corresponding source code.
- **Private use**: No restrictions (you don't need to share internally used modifications).

## Other dependencies

| Dependency | Upstream | License | GPL-3.0 Compatible? |
|---|---|---|---|
| `iso14443` | Foundation-Devices/iso14443-rs (forked) | GPL-3.0-or-later | Forces GPL-3.0 |
| `ntag424` | jannschu/ntag424 on Codeberg (forked) | MIT OR Apache-2.0 | Yes |
| `mfrc522` | crates.io `mfrc522` v0.8.0 (forked) | MIT OR Apache-2.0 | Yes |
| `pcsc` | bluetech/pcsc-rust | MIT | Yes |
| `embedded-hal` | rust-embedded/embedded-hal | MIT OR Apache-2.0 | Yes |
| `esp-idf-sys`/`esp-idf-hal` | esp-rs | Apache-2.0 | Yes |
| `heapless` | japaric/heapless | MIT OR Apache-2.0 | Yes |

All dependencies are compatible with GPL-3.0. The **only** dependency that
forces GPL-3.0 is `iso14443` (Foundation-Devices/iso14443-rs). If iso14443
were ever replaced with a permissively-licensed alternative, bolty-rs could
be relicensed to MIT OR Apache-2.0.

### Fork documentation

Amperstrand maintains forks of three dependencies, all with `ai-experiments`
as the default branch:

| Fork | Upstream | Changes | Issues |
|---|---|---|---|
| Amperstrand/iso14443-rs | Foundation-Devices/iso14443-rs | PcdSession, WTX timeout, protocol fixes | #1–#6 |
| Amperstrand/mfrc522-rs | crates.io mfrc522 v0.8.0 | I2C support, timer config | #1 |
| Amperstrand/ntag424 | jannschu/ntag424 (Codeberg) | Sdm::disabled(), LenCap=0x03 fix | #2–#4 |

## SPDX

`SPDX-License-Identifier: GPL-3.0-or-later`
