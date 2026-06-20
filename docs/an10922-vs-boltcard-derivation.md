# Key Derivation: AN10922 vs Boltcard Spec

## Overview

bolty-rs uses the **boltcard deterministic key derivation** spec ([DETERMINISTIC.md][1])
rather than NXP's official **AN10922** diversification. Both are valid AES-CMAC based
schemes, but they serve different purposes and are not interchangeable.

This document explains the difference, why bolty-rs chose the boltcard spec, and when
AN10922 would be preferable.

## AN10922 (NXP Official Diversification)

**Source**: NXP AN10922 §2.2 — *AES-128 Application Key Diversification*

AN10922 is NXP's recommended method for deriving per-card keys from a master key.
It is designed for general-purpose NTAG424 applications (access control, anti-counterfeiting).

### Derivation Formula

```
M = UID (7 bytes) || AID (7 bytes) || KeyNo (1 byte) || SystemIdentifier (variable)
D = 0x01 || M || Padding (0x80, 0x00...)
Key = AES-CMAC(MasterKey, D)
```

### Key Properties

- Uses **AES-CMAC** (RFC 4493) as the PRF
- Input includes **AID** (Application Identifier) and **SystemIdentifier** for domain separation
- Output is a single diversified key per (MasterKey, UID, KeyNo) tuple
- **One master key → one diversified key per card per key slot**

## Boltcard Spec (Deterministic Derivation)

**Source**: [boltcard/boltcard DETERMINISTIC.md][1]

The boltcard spec defines a specific key hierarchy for bolt card payment systems.
It uses domain-separation constants instead of AID/SystemIdentifier.

### Derivation Chain

```
IssuerKey (16 bytes, master seed)
    │
    ├── CardKey = AES-CMAC(IssuerKey, 0x2d003f75 || UID || Version_LE)
    │       │
    │       ├── K0 = AES-CMAC(CardKey, 0x2d003f76)
    │       ├── K2 = AES-CMAC(CardKey, 0x2d003f78)
    │       ├── K3 = AES-CMAC(CardKey, 0x2d003f79)
    │       └── K4 = AES-CMAC(CardKey, 0x2d003f7a)
    │
    ├── K1 = AES-CMAC(IssuerKey, 0x2d003f77)    ← same for ALL cards
    └── ID = AES-CMAC(IssuerKey, 0x2d003f7b || UID)
```

### Key Properties

- Uses **AES-CMAC** (same PRF as AN10922)
- Domain separation via hardcoded constants (`0x2d003f75` through `0x2d003f7b`)
- **Two-level hierarchy**: IssuerKey → CardKey → K0/K2/K3/K4
- **K1 is issuer-level** (shared across all cards) — enables server-side decryption without per-card lookup
- **Version parameter** enables key rotation without changing the master seed

## Comparison

| Property | AN10922 | Boltcard Spec |
|----------|---------|---------------|
| PRF | AES-CMAC (RFC 4493) | AES-CMAC (RFC 4493) |
| Domain separation | AID + SystemIdentifier | Fixed constants (0x2d003f75-7b) |
| Hierarchy depth | Flat (MasterKey → Key) | Two-level (Issuer → Card → Keys) |
| Key sharing | Per-card only | K1 shared, K2 per-card |
| Version rotation | Not specified | Built-in version parameter |
| Server optimization | Must try all cards | K1 decrypts any card's `p=` parameter |
| Standard | NXP official | Bolt card ecosystem de facto |

## Why bolty-rs Uses the Boltcard Spec

1. **Ecosystem compatibility**: The boltcard spec is used by [boltcard/boltcard][1],
   [BTCPayServer.BoltCardTools][2], [lnbits/boltcards][3], and the
   [boltcard-cloudflareworker][4]. Using AN10922 would make bolty-rs cards
   incompatible with these systems.

2. **Server-side efficiency**: K1 (shared across cards) lets the server decrypt
   any card's `p=` parameter without a per-card database lookup. The server only
   needs per-card data for K2 (CMAC verification).

3. **Version-based rotation**: The `version` parameter enables key rotation
   (re-provisioning) without changing the IssuerKey. AN10922 would require
   custom version handling.

4. **Privacy**: The `ID = AES-CMAC(IssuerKey, 0x2d003f7b || UID)` derivation
   lets the server track cards by a pseudonymous ID instead of the raw UID.

## When AN10922 Would Be Preferable

- **Non-bolt-card applications**: Access control, anti-counterfeiting, warranty seals
- **Multi-application systems**: Where AID-based separation is needed
- **Strict NXP compliance**: When certification requires official diversification
- **No shared key requirement**: When per-card K1 is acceptable

## Security Properties (Both Schemes)

Both schemes provide:
- **Key independence**: Compromising one card's keys does not reveal other cards' keys
- **Master key protection**: The master/issuer key never leaves the provisioning system
- **AES-128 security**: Based on RFC 4493 CMAC, which relies on AES-128 security

The boltcard spec's shared K1 is a deliberate trade-off: it enables server-side
efficiency at the cost of a broader blast radius if K1 is compromised. However,
K1 compromise only reveals UID+counter data (decryptable), not the ability to
forge valid CMACs (which requires K2).

## Test Vectors

The boltcard spec defines test vectors ([DETERMINISTIC.md §Test Vectors][1]):

```
Input:
  UID: 04a39493cc8680
  Issuer Key: 00000000000000000000000000000001
  Version: 1

Expected:
  K0: a29119fcb48e737d1591d3489557e49b
  K1: 55da174c9608993dc27bb3f30a4a7314
  K2: f4b404be700ab285e333e32348fa3d3b
  K3: 73610ba4afe45b55319691cb9489142f
  K4: addd03e52964369be7f2967736b7bdb5
  ID: e07ce1279d980ecb892a81924b67bf18
  CardKey: ebff5a4e6da5ee14cbfe720ae06fbed9
```

bolty-rs validates against these test vectors in `crates/bolty-core/tests/integration_assessment.rs`.

## References

- [1] [boltcard/boltcard DETERMINISTIC.md](https://github.com/boltcard/boltcard/blob/main/docs/DETERMINISTIC.md)
- [2] [BTCPayServer.BoltCardTools](https://github.com/btcpayserver/BTCPayServer.BoltCardTools)
- [3] [lnbits/boltcards](https://github.com/lnbits/boltcards)
- [4] boltcard-cloudflareworker (Amperstrand internal)
- [NXP AN10922](https://www.nxp.com/docs/en/application-note/AN10922.pdf) — AES-128 Application Key Diversification
- [RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493) — The AES-CMAC Algorithm
- [hackathon-tooling bip85-key-derivation.md](https://github.com/Amperstrand/hackathon-tooling/blob/main/patterns/boltcard/bip85-key-derivation.md)
