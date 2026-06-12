use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};

/// Derived keys for a boltcard, matching the TypeScript `@ntag424/crypto` key derivation exactly.
///
/// Derivation uses AES-128 CMAC (RFC 4493) with fixed constant prefixes:
/// - cardKey = CMAC(issuerKey, 0x2d003f75 || uid || version_le32)
/// - K0 = CMAC(cardKey, 0x2d003f76)
/// - K1 = CMAC(issuerKey, 0x2d003f77)
/// - K2 = CMAC(cardKey, 0x2d003f78)
/// - K3 = CMAC(cardKey, 0x2d003f79)
/// - K4 = CMAC(cardKey, 0x2d003f7a)
#[derive(Debug)]
pub struct DerivedKeys {
    pub k0: [u8; 16],
    pub k1: [u8; 16],
    pub k2: [u8; 16],
    pub k3: [u8; 16],
    pub k4: [u8; 16],
    pub card_key: [u8; 16],
}

/// Derive all five application keys from UID, issuer key, and version.
///
/// This must match the TypeScript `deriveKeysFromHex()` exactly.
pub fn derive_keys(uid: &[u8; 7], issuer_key: &[u8; 16], version: u32) -> DerivedKeys {
    let version_bytes = version.to_le_bytes();

    // cardKey = CMAC(issuerKey, 0x2d003f75 || uid || version_le32)
    let mut card_input = [0u8; 15];
    card_input[0..4].copy_from_slice(&[0x2d, 0x00, 0x3f, 0x75]);
    card_input[4..11].copy_from_slice(uid);
    card_input[11..15].copy_from_slice(&version_bytes);
    let card_key = cmac_16(issuer_key, &card_input);

    let k0 = cmac_16(&card_key, &[0x2d, 0x00, 0x3f, 0x76]);
    let k1 = cmac_16(issuer_key, &[0x2d, 0x00, 0x3f, 0x77]);
    let k2 = cmac_16(&card_key, &[0x2d, 0x00, 0x3f, 0x78]);
    let k3 = cmac_16(&card_key, &[0x2d, 0x00, 0x3f, 0x79]);
    let k4 = cmac_16(&card_key, &[0x2d, 0x00, 0x3f, 0x7a]);

    DerivedKeys {
        k0,
        k1,
        k2,
        k3,
        k4,
        card_key,
    }
}

/// Compute AES-128 CMAC and return exactly 16 bytes.
fn cmac_16(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).expect("valid 16-byte key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_keys_matches_typescript_test_vector() {
        // Test vector: UID=041065FA967380, IssuerKey=00000000000000000000000000000001, Version=1
        // Expected values verified byte-identical against @ntag424/crypto deriveKeysFromHex()
        let uid: [u8; 7] = hex::decode("041065fa967380")
            .expect("valid hex")
            .try_into()
            .expect("7 bytes");
        let issuer_key: [u8; 16] = hex::decode("00000000000000000000000000000001")
            .expect("valid hex")
            .try_into()
            .expect("16 bytes");

        let keys = derive_keys(&uid, &issuer_key, 1);

        // Full 16-byte equality — any mismatch means the derivation is wrong
        assert_eq!(
            hex::encode(keys.card_key),
            "36935834b525273e70a2d35b381ff4ad",
            "cardKey mismatch"
        );
        assert_eq!(
            hex::encode(keys.k0),
            "4b043f1ad0ea0c2be1ad1c4c9941ae28",
            "K0 mismatch"
        );
        assert_eq!(
            hex::encode(keys.k1),
            "55da174c9608993dc27bb3f30a4a7314",
            "K1 mismatch"
        );
        assert_eq!(
            hex::encode(keys.k2),
            "4ba55e62c51c26f32a42c97094533506",
            "K2 mismatch"
        );
        assert_eq!(
            hex::encode(keys.k3),
            "10ea6341ef3a59a941fa9bcea6e6c3cf",
            "K3 mismatch"
        );
        assert_eq!(
            hex::encode(keys.k4),
            "7f914368846e90bca0d3022564c9e24d",
            "K4 mismatch"
        );
    }
}
