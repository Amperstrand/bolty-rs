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

| Dependency | License | GPL-3.0 Compatible? |
|---|---|---|
| `ntag424` (Amperstrand) | MIT OR Apache-2.0 | Yes |
| `mfrc522` (Amperstrand fork) | MIT OR Apache-2.0 (upstream) | Yes |
| `pcsc` | MIT | Yes |
| `embedded-hal` | MIT OR Apache-2.0 | Yes |
| `esp-idf-sys`/`esp-idf-hal` | Apache-2.0 | Yes |
| `heapless` | MIT OR Apache-2.0 | Yes |

All dependencies are compatible with GPL-3.0. No additional licensing
constraints are imposed by any dependency.

## SPDX

`SPDX-License-Identifier: GPL-3.0-or-later`
