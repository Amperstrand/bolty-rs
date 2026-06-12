# bolty-cli Card Programming — Findings & Test Results

Date: 2025-06-12
Card: NTAG424 DNA, UID `041065FA967380`
Reader: ACS ACR1252 Dual Reader (PICC slot)
Worker: https://boltcardpoc.psbt.me
Issuer Key: `00000000000000000000000000000001` (dev default)

## Issues Found & Fixed

### Issue #1: SDM Key Slots (K3/K4 → K1/K2) — FIXED

**Discovery**: First burn used K3 for PICC encryption and K4 for CMAC.
Worker returned `"Unable to decode UID from provided p parameter."` because it
decrypts `p=` with K1 and verifies `c=` with K2.

**Root cause**: Comment in `burn.rs` said "K3 = PICC encryption, K4 = CMAC"
based on outdated AGENTS.md notes. Actual worker code in `boltCardHelper.ts`:
- `decryptP(pHex, k1Keys)` — K1 for PICC decryption
- `verifyCmac(uidBytes, ctr, cHex, k2Bytes)` — K2 for CMAC verification

**Fix**: Changed `boltcard_sdm_opts()` to use `KeyNumber::Key1` / `KeyNumber::Key2`.

### Issue #2: MAC Input Window (non-empty → empty) — FIXED

**Discovery**: Card CMAC `F29C7EF8F625D096` didn't match TypeScript library's
expected `1ee6eb6b1415af21` for the same UID + counter + K2.

**Root cause**: The URL template `?p={picc:uid+ctr}&c={mac}` without the `[[`
marker caused the ntag424 crate to set `MacWindow { input: Offset(26), mac: Offset(65) }`.
The card included 39 bytes of file data (`?p=...&c=`) in the MAC computation,
but `@ntag424/crypto`'s `verifyCmac()` assumes an empty sdmmacinput
(it computes CMAC with zero-length input via `_computeCm()` which XORs K2' with
`[0x80, 0, ...]` — the RFC 4493 padding for empty message).

**Fix**: Changed template to `?p={picc:uid+ctr}&c=[[{mac}`. The `[[` is an
ntag424 crate template directive that sets the MAC input offset to the same
position as the MAC itself, creating a zero-length window:
`MacWindow { input: Offset(65), mac: Offset(65) }`.

**Spec reference**: NXP NTAG424 DNA AN12196 §3.4.3 — sdmmacinput length
determines whether the card includes file data in the MAC. Empty input =
session-key-only MAC.

### Issue #3: PCSC Reader Selection (SAM → PICC) — FIXED

**Discovery**: `PcscTransport::connect()` used `readers.first()` which selected
the SAM slot on the ACS ACR1252 Dual Reader. Error: `"no card present in reader:
ACS ACR1252 Dual Reader SAM"`.

**Fix**: Reader selection now prefers "PICC" readers, skips "SAM" readers,
falls back to first available.

### Issue #4: Test Vectors — Prefix-Only → Full 16-Byte Equality — FIXED

**Discovery**: `keys.rs` tests only verified first 4 hex chars of each derived key
(`starts_with("4b043f1a")`). This could pass with a partially broken derivation.

**Fix**: Tests now assert full 16-byte key equality against verified test vectors
from `@ntag424/crypto deriveKeysFromHex()`.

### Issue #5: Wipe NDEF Format — [0u8; 8] → [0x00, 0x00] — FIXED

**Discovery**: Wipe flow wrote 8 zero bytes as empty NDEF. The NDEF Type 4 Tag
spec (NFC Forum T4TOP §4.1) specifies the file starts with a 2-byte NLEN field
(big-endian length of the NDEF message). An empty file = NLEN=0 = `[0x00, 0x00]`.

**Fix**: Changed `let empty_ndef = [0u8; 8]` to `let empty_ndef = [0x00u8, 0x00]`.

### Issue #6: Misleading Comment — `uid[7]` → `uid` — FIXED

**Discovery**: Comment in `keys.rs` said `uid[7]` suggesting array indexing,
but `uid` is a `[u8; 7]` slice covering indices 0-6.

**Fix**: Changed comment to `uid` (the full 7-byte slice).

### Issue #7: SDM Not Cleared by `into_update()` — FIXED

**Discovery**: After changing file settings during burn, SDM data from the previous
configuration persisted on the card. The burn verification failed because SDM was
still active despite calling `into_update()` without `.with_sdm()`.

**Root cause**: The ntag424 crate's `FileSettingsBuilder::into_update()` preserves
existing SDM settings when `.with_sdm()` is not called — it does NOT clear them.
This is surprising because the builder pattern implies omission = disabled.

**Fix**: Explicitly call `.with_sdm(disabled_sdm())` where `disabled_sdm()` returns
`Sdm::try_new(PiccData::None, None, None, CryptoMode::Aes)`. This sets bit 6 in
file_option (required for card to process SDM fields) but writes all-disabled values
(0xF nibbles for SDM offsets).

**Impact**: Without this fix, burned cards retain residual SDM configuration that
could leak data or cause validation failures on subsequent operations.

### Issue #8: NDEF Verification Compares Full 256 Bytes — FIXED

**Discovery**: Post-burn NDEF verification read 256 bytes and compared the entire
buffer against the expected NDEF message, failing if any byte differed.

**Root cause**: NDEF files on NTAG424 may have trailing bytes from previous writes
or manufacturer defaults. The NFC Forum Type 4 spec says only the first 2 bytes
(NLEN) + NLEN bytes of NDEF message are meaningful — bytes beyond NLEN+NLEN are
inert and undefined.

**Fix**: Only verify the first `ndef_message.len()` bytes instead of the full 256-byte
read. Trailing bytes are ignored per NFC Forum Type 4 Tag Operation specification §4.1.

### Issue #9: Residual SDM in Re-burn — FIXED

**Discovery**: When re-burning a previously burned card, SDM configuration from the
old burn persisted through the burn sequence because file settings change (which
sets SDM) happened after NDEF write but the old SDM was still active during the
intermediate state.

**Root cause**: The burn sequence wrote NDEF first, then changed file settings
(including SDM). Between these operations, the card had the old SDM config pointing
at offsets from the previous burn, potentially causing the card to include stale
file data in SDM computations.

**Fix**: Clear residual SDM at the start of the burn sequence, before writing NDEF:
```rust
let disabled = disabled_sdm();
card.change_file_settings(2, FileSettingsBuilder::from(file_settings)
    .with_sdm(&disabled)
    .into_update())?;
```
Then proceed with NDEF write and final file settings change with the intended SDM
configuration. Also added post-burn and post-wipe verification steps that:
- Burn: auth new K0, verify SDM is active with correct offsets
- Wipe: auth factory K0, verify SDM functionally disabled (PiccData::None, no file_read),
  verify NDEF NLEN=0

## Non-Issues (Confirmed Working)

### Receipt Endpoint "Empty Response"

**Discovery**: `GET /api/receipt/2` returned empty response.

**Root cause**: Test was missing two things:
1. `?uid=041065fa967380` query parameter (required by `receiptHandler.ts` line 18)
2. Operator session cookie (endpoint is behind `withOperatorAuth` middleware)

**Status**: Not a code bug — receipt works correctly with proper params:
`GET /api/receipt/2?uid=041065fa967380` + operator session → 200 with receipt text.

### Issuer Key Validation

**Discovery**: Explore agent flagged missing input validation on issuer key.

**Status**: Already implemented in `parse_hex_16()` at `main.rs:58-65` — validates
exact 32-char length and hex decoding. Not an issue.

### Replay Detection "Not Working"

**Discovery**: Same URL submitted twice was accepted both times.

**Status**: By design — replay enforcement is disabled in the worker config
(`lnurlwHandler.ts` line 86: `"continuing because replay enforcement is disabled"`).
The worker logs a warning but returns the withdraw request.

## End-to-End Test Results

| # | Test | Result | Details |
|---|------|--------|---------|
| 1 | Card tap (LNURL-withdraw) | ✅ 200 | `withdrawRequest` with callback |
| 2 | Second tap (counter advance) | ✅ 200 | Counter auto-increments |
| 3 | Replay (same URL) | ✅ 200 | Accepted (enforcement disabled) |
| 4 | Top-up 1000 credits | ✅ 200 | Balance 0→1000 |
| 5 | Balance check | ✅ 200 | Reports correct balance |
| 6 | Card info + history | ✅ 200 | Full history with timestamps |
| 7 | POS charge 250 | ✅ 200 | Balance 1000→750 |
| 8 | Over-draft (1000 > 750) | ✅ 402 | "Insufficient balance" |
| 9 | Refund 750 | ✅ 200 | Balance 750→1500 |
| 10 | LNURL callback (fakewallet) | ✅ 200 | Debited 100, balance 1400 |
| 11 | Wrong CMAC | ✅ 403 | "CMAC validation failed" |
| 12 | Missing params | ✅ ERROR | Proper error message |
| 13 | Garbage p parameter | ✅ ERROR | "Invalid p length" |
| 14 | Receipt (with auth + uid) | ✅ 200 | Plain text receipt |
| 15 | Wipe + re-burn | ✅ | Card fully reset and reprogrammed |

## Test Setup

```bash
# Read card
cargo +stable run -p bolty-cli -- inspect

# Extract live URL
python3 -c "
h='<NDEF hex from inspect>'
data=bytes.fromhex(h)
picc=data[30:62].decode('ascii')   # SDM PICC at offset 30, 32 chars
mac=data[65:81].decode('ascii')    # SDM MAC at offset 65, 16 chars
print(f'https://boltcardpoc.psbt.me/?p={picc}&c={mac}')
"

# Test tap
curl "https://boltcardpoc.psbt.me/?p=<PICC>&c=<CMAC>"

# Operator login (form-encoded)
curl -c cookies.txt -X POST "https://boltcardpoc.psbt.me/operator/login" \
  -d "pin=1234"

# Get CSRF (from first GET to operator page)
curl -c cookies.txt -b cookies.txt "https://boltcardpoc.psbt.me/operator/topup" > /dev/null
CSRF=$(grep op_csrf cookies.txt | awk '{print $NF}')

# Top-up
curl -b cookies.txt -X POST "https://boltcardpoc.psbt.me/operator/topup/apply" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"p":"<PICC>","c":"<CMAC>","amount":1000}'

# Balance check (no auth)
curl -X POST "https://boltcardpoc.psbt.me/api/balance-check" \
  -H "Content-Type: application/json" \
  -d '{"p":"<PICC>","c":"<CMAC>"}'
```
