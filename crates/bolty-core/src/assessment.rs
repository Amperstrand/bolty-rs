/// High-level outcome of issuer/key assessment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CardState {
    #[default]
    Unknown,
    Blank,
    Provisioned(usize),
    Foreign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssessmentError {
    InvalidUidLength,
    KeyVersionMismatch,
}

/// What kind of card is currently in the reader field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleCardKind {
    None,
    Blank,
    Provisioned,
    Unknown,
    Inconsistent,
}

/// Confidence level of an issuer match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyConfidence {
    None,
    K1Only,
    Full,
}

/// Result of assessing a card in the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardAssessment {
    pub state: CardState,
    pub present: bool,
    pub is_ntag424: bool,
    pub uid: Option<[u8; 12]>,
    pub uid_len: u8,
    pub kind: IdleCardKind,
    pub key_versions: [u8; 5],
    pub key_confidence: [KeyConfidence; 5],
    pub zero_key_auth_ok: bool,
    pub has_ndef: bool,
    pub has_uri: bool,
    pub looks_like_boltcard: bool,
    pub deterministic_k1_match: bool,
    pub deterministic_full_match: bool,
    pub reset_eligible: bool,
}

impl Default for CardAssessment {
    fn default() -> Self {
        Self {
            state: CardState::Unknown,
            present: false,
            is_ntag424: false,
            uid: None,
            uid_len: 0,
            kind: IdleCardKind::Unknown,
            key_versions: [0u8; 5],
            key_confidence: [KeyConfidence::None; 5],
            zero_key_auth_ok: false,
            has_ndef: false,
            has_uri: false,
            looks_like_boltcard: false,
            deterministic_k1_match: false,
            deterministic_full_match: false,
            reset_eligible: false,
        }
    }
}

impl CardAssessment {
    /// Reset the assessment to its initial state, matching C++ reset_card_assessment().
    /// All key_versions are set to 0xFF, key_confidence to None, and kind to Unknown.
    pub fn reset(&mut self) {
        self.state = CardState::Unknown;
        self.present = false;
        self.is_ntag424 = false;
        self.uid = None;
        self.uid_len = 0;
        self.kind = IdleCardKind::Unknown;
        self.key_versions = [0xFF; 5];
        self.key_confidence = [KeyConfidence::None; 5];
        self.zero_key_auth_ok = false;
        self.has_ndef = false;
        self.has_uri = false;
        self.looks_like_boltcard = false;
        self.deterministic_k1_match = false;
        self.deterministic_full_match = false;
        self.reset_eligible = false;
    }
}

/// Compare a scanned UID against a stored assessment using constant-time comparison.
/// Returns true if the card is present and the UIDs match exactly.
pub fn same_uid(assessment: &CardAssessment, uid: &[u8; 7]) -> bool {
    if !assessment.present || assessment.uid_len != 7 {
        return false;
    }

    match &assessment.uid {
        Some(stored_uid) => {
            // Constant-time comparison to prevent timing attacks
            let mut result: u8 = 0;
            for i in 0..7 {
                result |= stored_uid[i] ^ uid[i];
            }
            result == 0
        }
        None => false,
    }
}

#[cfg(test)]
mod assessment_model {
    use super::*;

    #[test]
    fn default_is_unknown() {
        let assessment = CardAssessment::default();
        assert_eq!(assessment.state, CardState::Unknown);
        assert_eq!(assessment.kind, IdleCardKind::Unknown);
    }

    #[test]
    fn reset_sets_versions_to_ff() {
        let mut assessment = CardAssessment::default();
        assessment.reset();

        // After reset, all key versions should be 0xFF
        assert_eq!(assessment.key_versions, [0xFFu8; 5]);
    }

    #[test]
    fn reset_sets_confidence_to_none() {
        let mut assessment = CardAssessment::default();
        assessment.reset();

        // After reset, all key confidence should be None
        assert_eq!(assessment.key_confidence, [KeyConfidence::None; 5]);
    }

    #[test]
    fn reset_sets_kind_to_unknown() {
        let mut assessment = CardAssessment::default();
        assessment.reset();

        assert_eq!(assessment.kind, IdleCardKind::Unknown);
    }

    #[test]
    fn blank_card_construction() {
        let assessment = CardAssessment {
            kind: IdleCardKind::Blank,
            zero_key_auth_ok: true,
            key_versions: [0x00; 5],
            ..Default::default()
        };

        assert_eq!(assessment.kind, IdleCardKind::Blank);
        assert!(assessment.zero_key_auth_ok);
        assert_eq!(assessment.key_versions, [0x00; 5]);
    }

    #[test]
    fn provisioned_card_construction() {
        let assessment = CardAssessment {
            kind: IdleCardKind::Provisioned,
            key_versions: [0x01; 5],
            key_confidence: [KeyConfidence::Full; 5],
            looks_like_boltcard: true,
            ..Default::default()
        };

        assert_eq!(assessment.kind, IdleCardKind::Provisioned);
        assert_eq!(assessment.key_versions, [0x01; 5]);
        assert_eq!(assessment.key_confidence, [KeyConfidence::Full; 5]);
        assert!(assessment.looks_like_boltcard);
    }

    #[test]
    fn same_uid_matches_when_present_and_equal() {
        let test_uid: [u8; 7] = [0x04, 0x96, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];
        let mut uid_array: [u8; 12] = [0; 12];
        uid_array[..7].copy_from_slice(&test_uid);
        let assessment = CardAssessment {
            present: true,
            uid_len: 7,
            uid: Some(uid_array),
            ..Default::default()
        };

        assert!(same_uid(&assessment, &test_uid));
    }

    #[test]
    fn same_uid_returns_false_when_not_present() {
        let assessment = CardAssessment::default();
        let test_uid: [u8; 7] = [0x04, 0x96, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];

        assert!(!same_uid(&assessment, &test_uid));
    }

    #[test]
    fn same_uid_returns_false_when_uid_len_mismatch() {
        let test_uid: [u8; 7] = [0x04, 0x96, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];
        let mut uid_array: [u8; 12] = [0; 12];
        uid_array[..7].copy_from_slice(&test_uid);
        let assessment = CardAssessment {
            present: true,
            uid_len: 4,
            uid: Some(uid_array),
            ..Default::default()
        };

        assert!(!same_uid(&assessment, &test_uid));
    }

    #[test]
    fn same_uid_returns_false_when_uid_mismatch() {
        let test_uid: [u8; 7] = [0x04, 0x96, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];
        let mut different_uid: [u8; 12] = [0; 12];
        different_uid[..7].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let assessment = CardAssessment {
            present: true,
            uid_len: 7,
            uid: Some(different_uid),
            ..Default::default()
        };

        assert!(!same_uid(&assessment, &test_uid));
    }
}
