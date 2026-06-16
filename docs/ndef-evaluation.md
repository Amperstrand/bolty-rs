# NDEF Library Evaluation

## Decision: KEEP our custom parser — do NOT adopt ndef-rs

Evaluated: [Foundation-Devices/ndef-rs](https://github.com/Foundation-Devices/ndef-rs) v0.5.0

## Why we're keeping our code

Our `parse_ndef_uri()` (bolty-ntag/src/lib.rs, 55 lines) is purpose-built for Bolt Cards:
- Parses only URI records (the only type NTAG424 DNA Bolt Cards use)
- Extracts `p=` and `c=` query parameters (Bolt Card SDM specific)
- Zero external dependencies
- 13 unit tests covering edge cases (short/long records, truncated data, wrong types)

ndef-rs is general-purpose:
- Handles ALL NDEF record types (Text, URI, Smart Poster, external)
- Adds 4 dependencies: `dcbor`, `derive_more`, `rustversion`, `heapless`
- Would need a wrapper to extract `p=`/`c=` parameters
- Overkill for our use case

The 4 extra dependencies aren't justified for replacing a 55-line function that works correctly and is well-tested.

## When to reconsider

Adopt ndef-rs if we need to:
- Parse non-URI NDEF records (e.g., Text records for card metadata)
- Create NDEF messages programmatically (currently handled by ntag424's `sdm_url_config()`)
- Support Smart Poster records (multi-record NDEF messages)

None of these are needed for Bolt Card programming.
