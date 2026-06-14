use crate::util::{HexError, decode_hex};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CardUid([u8; 7]);

impl CardUid {
    pub const fn new(bytes: [u8; 7]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 7] {
        &self.0
    }

    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        decode_hex::<7>(s).map(Self)
    }
}

impl From<[u8; 7]> for CardUid {
    fn from(bytes: [u8; 7]) -> Self {
        Self(bytes)
    }
}

impl From<CardUid> for [u8; 7] {
    fn from(uid: CardUid) -> Self {
        uid.0
    }
}

impl core::fmt::Debug for CardUid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CardUid(")?;
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        write!(f, ")")
    }
}

impl core::fmt::Display for CardUid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CardUid;

    #[test]
    fn new_preserves_bytes() {
        let raw = [0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80];
        let uid = CardUid::new(raw);
        assert_eq!(uid.as_bytes(), &raw);
    }

    #[test]
    fn from_hex_valid() {
        let uid = CardUid::from_hex("04a39493cc8680").unwrap();
        assert_eq!(uid.as_bytes(), &[0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80]);
    }

    #[test]
    fn from_hex_wrong_length() {
        assert!(CardUid::from_hex("04a394").is_err());
    }

    #[test]
    fn from_hex_invalid_chars() {
        assert!(CardUid::from_hex("XXa39493cc8680").is_err());
    }

    #[test]
    fn debug_shows_hex() {
        let uid = CardUid::new([0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80]);
        assert_eq!(format!("{uid:?}"), "CardUid(04A39493CC8680)");
    }

    #[test]
    fn display_shows_lowercase_hex() {
        let uid = CardUid::new([0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80]);
        assert_eq!(format!("{uid}"), "04a39493cc8680");
    }

    #[test]
    fn from_and_into_array() {
        let raw = [0x01; 7];
        let uid = CardUid::from(raw);
        assert_eq!(uid.as_bytes(), &raw);
        let back: [u8; 7] = uid.into();
        assert_eq!(back, raw);
    }

    #[test]
    fn equality() {
        let a = CardUid::new([0x01; 7]);
        let b = CardUid::new([0x01; 7]);
        let c = CardUid::new([0x02; 7]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
