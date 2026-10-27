// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! NXP Originality Signature verification (AN12196 §7.2).
//!
//! ECDSA over `secp224r1` (NIST P-224) against the raw 7-byte UID. No hash
//! function is applied: the UID is zero-extended on the left to the 28-byte
//! P-224 scalar-field width and used directly as the ECDSA integer `z`
//! (matching the pattern used by other NXP originality-signature chips).
//! The signature is returned by `Cmd.Read_Sig` (INS = `3C`) as 56 raw bytes
//! (`r ‖ s`, 28 bytes each, big-endian). The public key below is the
//! NXP-wide master key for NTAG 424 DNA.

use p224::ecdsa::signature::hazmat::PrehashVerifier;
use p224::ecdsa::{Signature, VerifyingKey};

// The wire length of a `Read_Sig` response lives in `crate::types` (the
// command layer must compile without this module); re-exported here for
// the historical `crypto::originality::SIGNATURE_LEN` path.
pub use crate::types::SIGNATURE_LEN;

/// NXP's NTAG 424 DNA originality public key.
///
/// Stored in SEC1 uncompressed form (`0x04 ‖ xD ‖ yD`). Source:
/// AN12196 §7.2, Table 30.
pub const NXP_ORIGINALITY_PUBLIC_KEY_SEC1: [u8; 57] = [
    0x04, 0x8A, 0x9B, 0x38, 0x0A, 0xF2, 0xEE, 0x1B, 0x98, 0xDC, 0x41, 0x7F, 0xEC, 0xC2, 0x63, 0xF8,
    0x44, 0x9C, 0x76, 0x25, 0xCE, 0xCE, 0x82, 0xD9, 0xB9, 0x16, 0xC9, 0x92, 0xDA, 0x20, 0x9D, 0x68,
    0x42, 0x2B, 0x81, 0xEC, 0x20, 0xB6, 0x5A, 0x66, 0xB5, 0x10, 0x2A, 0x61, 0x59, 0x6A, 0xF3, 0x37,
    0x92, 0x00, 0x59, 0x93, 0x16, 0xA0, 0x0A, 0x14, 0x10,
];

/// P-224 scalar-field byte width - size of the zero-extended prehash.
const FIELD_BYTES: usize = 28;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OriginalityError {
    /// UID is longer than the P-224 scalar-field width (28 bytes).
    UidTooLong,
    /// Public key or signature bytes are not a well-formed curve element.
    Malformed,
    /// Signature did not verify under the supplied public key.
    VerificationFailed,
}

/// A 56-byte P-224 ECDSA originality signature read from an NTAG 424 DNA tag.
///
/// Wraps the raw `r ‖ s` bytes and exposes methods to verify them against a UID.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OriginalitySignature([u8; SIGNATURE_LEN]);

impl OriginalitySignature {
    /// Wrap raw signature bytes (e.g. from deserialization or testing).
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 56-byte signature (`r ‖ s`, 28 bytes each, big-endian).
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Verify against the NXP NTAG 424 DNA master public key (AN12196 §7.2).
    pub fn verify(&self, uid: &[u8]) -> Result<(), OriginalityError> {
        verify_with_key(&NXP_ORIGINALITY_PUBLIC_KEY_SEC1, uid, &self.0)
    }

    /// Verify against a caller-supplied SEC1-encoded public key.
    ///
    /// `public_key_sec1` may be in compressed (`0x02`/`0x03`) or
    /// uncompressed (`0x04`) form.
    pub fn verify_with_key(
        &self,
        public_key_sec1: &[u8],
        uid: &[u8],
    ) -> Result<(), OriginalityError> {
        verify_with_key(public_key_sec1, uid, &self.0)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for OriginalitySignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for OriginalitySignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = OriginalitySignature;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{SIGNATURE_LEN} bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; SIGNATURE_LEN]>::try_from(v)
                    .map(OriginalitySignature)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut buf = [0u8; SIGNATURE_LEN];
                for (i, slot) in buf.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(OriginalitySignature(buf))
            }
        }
        d.deserialize_bytes(SigVisitor)
    }
}

/// Verify a signature with a caller-supplied public key.
///
/// `public_key_sec1` may be SEC1-encoded in compressed (`0x02`/`0x03`)
/// or uncompressed (`0x04`) form.
fn verify_with_key(
    public_key_sec1: &[u8],
    uid: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), OriginalityError> {
    if uid.len() > FIELD_BYTES {
        return Err(OriginalityError::UidTooLong);
    }
    let key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| OriginalityError::Malformed)?;
    let sig = Signature::from_slice(signature).map_err(|_| OriginalityError::Malformed)?;

    // Zero-extend the UID on the left to the P-224 field width. ecdsa's
    // `verify_prehash` would otherwise expect at least FIELD_BYTES bytes.
    let mut prehash = [0u8; FIELD_BYTES];
    prehash[FIELD_BYTES - uid.len()..].copy_from_slice(uid);

    key.verify_prehash(&prehash, &sig)
        .map_err(|_| OriginalityError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // AN12196 §7.2, Table 30.
    const TABLE30_UID: [u8; 7] = [0x04, 0x51, 0x8D, 0xFA, 0xA9, 0x61, 0x80];
    const TABLE30_SIG: [u8; SIGNATURE_LEN] = [
        0xD1, 0x94, 0x0D, 0x17, 0xCF, 0xED, 0xA4, 0xBF, 0xF8, 0x03, 0x59, 0xAB, 0x97, 0x5F, 0x9F,
        0x65, 0x14, 0x31, 0x3E, 0x8F, 0x90, 0xC1, 0xD3, 0xCA, 0xAF, 0x59, 0x41, 0xAD, 0x74, 0x4A,
        0x1C, 0xDF, 0x9A, 0x83, 0xF8, 0x83, 0xCA, 0xFE, 0x0F, 0xE9, 0x5D, 0x19, 0x39, 0xB1, 0xB7,
        0xE4, 0x71, 0x13, 0x99, 0x33, 0x24, 0x47, 0x3B, 0x78, 0x5D, 0x21,
    ];

    #[cfg(feature = "serde")]
    mod serde_tests {
        use super::*;
        use serde::Deserialize as _;
        use serde::de::value::{BorrowedBytesDeserializer, Error as DeError};

        #[test]
        fn json_roundtrip() {
            let sig = OriginalitySignature::from_bytes(TABLE30_SIG);
            let json = serde_json::to_string(&sig).expect("serialize");
            let got: OriginalitySignature = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(sig, got);
        }

        #[test]
        fn deserialize_from_bytes_visitor() {
            let sig = OriginalitySignature::from_bytes(TABLE30_SIG);
            let de = BorrowedBytesDeserializer::<DeError>::new(&TABLE30_SIG);
            let got = OriginalitySignature::deserialize(de).expect("deserialize from bytes");
            assert_eq!(sig, got);
        }

        #[test]
        fn deserialize_wrong_length_is_error() {
            let de = BorrowedBytesDeserializer::<DeError>::new(&TABLE30_SIG[..10]);
            assert!(OriginalitySignature::deserialize(de).is_err());
        }
    }

    #[test]
    fn an12196_table30_vector() {
        OriginalitySignature::from_bytes(TABLE30_SIG)
            .verify(&TABLE30_UID)
            .expect("AN12196 Table 30 signature must verify");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "P-224 ECDSA verify; covered by an12196_table30_vector under miri"
    )]
    fn rejects_flipped_signature() {
        let mut sig = TABLE30_SIG;
        sig[0] ^= 0x01;
        assert_eq!(
            OriginalitySignature::from_bytes(sig).verify(&TABLE30_UID),
            Err(OriginalityError::VerificationFailed)
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "P-224 ECDSA verify; covered by an12196_table30_vector under miri"
    )]
    fn rejects_wrong_uid() {
        let mut uid = TABLE30_UID;
        uid[6] ^= 0x01;
        assert_eq!(
            OriginalitySignature::from_bytes(TABLE30_SIG).verify(&uid),
            Err(OriginalityError::VerificationFailed)
        );
    }
}
