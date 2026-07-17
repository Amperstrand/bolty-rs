# Key Derivation: AN10922 vs Boltcard Spec

## Decision

bolty-rs uses the **boltcard spec** key derivation, not NXP AN10922. This is
required for interoperability with the bolt card payment ecosystem.

## The Two Approaches

### Boltcard Spec (used by bolty-rs)

```
CardKey = AES-CMAC(IssuerKey, TAG_CARD_KEY || UID || Version)
K0     = AES-CMAC(IssuerKey, TAG_K0 || UID || Version)
K1     = AES-CMAC(IssuerKey, TAG_K1 || UID || Version)
K2     = AES-CMAC(IssuerKey, TAG_K2 || UID || Version)
K3     = AES-CMAC(IssuerKey, TAG_K3 || UID || Version)
K4     = AES-CMAC(IssuerKey, TAG_K4 || UID || Version)
CardID = AES-CMAC(IssuerKey, TAG_CARD_ID || UID || Version)
```

Domain separation constants (all share prefix `0x2D 0x00 0x3F`):

| Key    | Tag bytes          |
|--------|--------------------|
| CardKey | `2D 00 3F 75`     |
| K0      | `2D 00 3F 76`     |
| K1      | `2D 00 3F 77`     |
| K2      | `2D 00 3F 78`     |
| K3      | `2D 00 3F 79`     |
| K4      | `2D 00 3F 7A`     |
| CardID  | `2D 00 3F 7B`     |

**Properties:**
- Each key derived independently from IssuerKey (no chaining)
- Version byte enables key rotation without changing IssuerKey
- UID is 7 bytes, Version is 1 byte (little-endian in CMAC input)

### AN10922 (NXP Official)

```
Key = AES-CMAC(MasterKey, 0x01 || UID || AID || KeyNo || SystemIdentifier || Padding)
```

**Properties:**
- Single derivation formula for all keys — KeyNo differentiates
- Includes AID (Application Identifier) and SystemIdentifier in the input
- Standardized in NXP Application Note 10922 §2.2
- Padding follows AES-CMAC standard (RFC 4493)

## Cryptographic Comparison

Both approaches use AES-128-CMAC as the derivation primitive. The security
properties are equivalent:

| Property | Boltcard | AN10922 |
|----------|----------|---------|
| Primitive | AES-128-CMAC | AES-128-CMAC |
| Key length | 128-bit | 128-bit |
| Domain separation | Tag prefix (0x2D003F**) | 0x01 + AID + SystemIdentifier |
| UID binding | ✓ | ✓ |
| Key rotation | Version byte | KeyNo |
| Pseudorandom output | ✓ (CMAC is a PRF) | ✓ |

Neither approach is cryptographically weaker than the other. The difference
is purely in the domain separation scheme — boltcard uses fixed 4-byte tags,
AN10922 uses a structured header with AID and SystemIdentifier fields.

## Why bolty-rs Uses Boltcard Spec

1. **Ecosystem compatibility**: Bolt cards provisioned by bolty-rs must
   interoperate with boltcard/boltcard, wbits/cardos, and other implementations
   that use the boltcard derivation. Using AN10922 would produce different
   keys — cards provisioned by bolty-rs would not work with other tools.

2. **Simplicity**: The boltcard derivation is simpler — no AID or
   SystemIdentifier configuration needed. The 4-byte tags are hardcoded
   constants.

3. **Key rotation**: The Version byte provides clean key rotation — change
   the version, all keys change, but the IssuerKey stays the same. This
   matches the bolt card recovery workflow (try-key with different versions).

4. **Card ID derivation**: The boltcard spec includes CardID derivation
   (TAG_CARD_ID), which provides a deterministic identifier for audit
   logging. AN10922 does not specify a card identifier derivation.

## When AN10922 Would Be Preferable

- **Non-bolt-card deployments**: If using NTAG424 for a different
  application (access control, transit, identity), AN10922 is the
  NXP-recommended approach and provides better interoperability with
  NXP tools and documentation.

- **Multi-application cards**: AN10922's AID field allows multiple
  applications to share a card without key collision. The boltcard
  derivation does not have this concept.

- **Regulatory compliance**: Some certifications may require the
  NXP-standardized derivation rather than a community spec.

## Implementation Details

bolty-rs implements the boltcard derivation in
`crates/bolty-core/src/derivation.rs`:

- `KeyDerivation::derive_card_key()` — derives CardKey from IssuerKey + UID + Version
- `KeyDerivation::derive_keys()` — derives full CardKeySet (K0-K4 + CardKey + CardID)
- `KeyDerivation::derive_card_id()` — derives CardID for audit logging

The `DerivationStrategy::Boltcard` enum variant selects this derivation.
A `DerivationStrategy::An10922` variant exists for low-level compatibility
but delegates to the ntag424 crate's AN10922 implementation.

## Test Vectors

Cross-validation vectors are in `tests/fixtures/derivation/boltcard_deterministic.toml`.
These verify that bolty-rs produces the same keys as the reference
boltcard/boltcard implementation.

## References

- [boltcard/boltcard DETERMINISTIC.md](https://github.com/boltcard/boltcard/blob/master/DETERMINISTIC.md)
- [NXP AN10922 §2.2](https://www.nxp.com/docs/en/application-note/AN10922.pdf)
- [ntag424 Rust crate — key_diversification module](https://github.com/Amperstrand/ntag424)
- [RFC 4493 — AES-CMAC](https://tools.ietf.org/html/rfc4493)
