# Rig integration — the SUN read path (boltcard-rig lane)

Status: verified 2026-10-17 against main `dab2f1a`. Role split: the
boltcard-rig lane (ai-legion) owns card-emulation + the worker side;
**bolty-rs is the reader/verification side** — it consumes the NTAG424
SUN (Secure Unique NFC) authentication that an emulated or real card
presents in its NDEF URL.

## Where the read path lives

`bolty_core::picc` (`crates/bolty-core/src/picc.rs`) — **pure host-side
library logic**, no esp-idf, no PCSC, no allocator tricks: it builds in
the host test suite (21 picc tests), in `bolty-cli`, and inside the
ESP32 firmware alike. The rig consumes it as a git/path dependency on
`bolty-core`, exactly like the CLI does.

## The consumption contract

```rust
use bolty_core::picc::picc_parse_url;

let picc = picc_parse_url(&k1, &k2, url);   // PiccData { valid, uid, counter, .. }
```

| Input | Meaning | Source on a real deployment |
|---|---|---|
| `k1: [u8; 16]` | SDM Meta Read Access Key — decrypts the `p=` parameter (AES-128-CBC, zero IV) | Deterministic derivation: `K1 = PRF(IssuerKey, '2d003f77')` (`bolty_core::derivation`) |
| `k2: [u8; 16]` | SDM File Read Access Key — verifies the `c=` SUN MAC (double AES-CMAC over SV2) | `K2 = PRF(CardKey, '2d003f78')` |
| `url: &str` | The NDEF URI the card mirrored (`...?p=<32 hex>&c=<16 hex>`) | The emulated tag's NDEF content |

`PiccData.valid == true` means the full chain held: `p=` decrypted to a
well-formed PICCData (`0xC7` tag / `0x40` no-UID variant, §-pinned
layout) **and** the `c=` CMAC verified over SV2(uid ‖ counter). The
counter is surfaced for the service-side monotonicity check (BOLT_SPEC:
"the bolt card service must only accept an increasing counter value").

Command-line equivalent (also the smoke test for this contract):

```bash
cargo run -p bolty-core --example picc_verify -- <k1-hex> <k2-hex> '<url>'
```

## Host-side status (why no extraction was needed)

The repo's host-compilable discipline already placed this path in the
pure core: `picc.rs` carries the spec quote-locks, byte-exact fixture
vectors (`tests/fixtures/picc/valid_picc.toml`, incl. the no-UID
AN12196 variants), and a cross-implementation audit note against the Go
boltcard `check_cmac`. Nothing is firmware-locked; the firmware's
`picc` command and the CLI's `inspect` SDM path both call the same
library functions.

## Fuzz coverage (#86 phase 1 — parser/auth pure functions)

`fuzz/` (nightly cargo-fuzz, not part of the stable workspace):

| Target | Path exercised |
|---|---|
| `picc_parse_url` | full chain: extract → decrypt → CMAC verify |
| `picc_decrypt_p` | SUN encrypted-part decode, hostile plaintext/tags |
| `picc_verify_c` | chained decrypt→verify with hostile MACs |
| `parse_ndef_uri` | NDEF T4T NLEN/record parsing (hostile lengths) |
| `standardize_url_template` | burn-side URL template normalization |

Seeds include the fixture vectors and an openssl-generated valid
ciphertext chain. The **differential leg** (ACR1252U as oracle, nucula
capture corpora as seeds) is deliberately NOT here — it is queued
behind the rig lane's ACR1252 ownership (issue #86 phase 2).
