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

/// Formal card lifecycle state machine.
///
/// States follow the bolty-rs operational model:
/// `Blank` → `Provisioned` → `HalfWiped` → `AuthDelay` (transient).
///
/// This is the type-backed counterpart of the string classifier
/// `diagnose::classify_card_state`; [`Self::from_signals`] reproduces that
/// function's logic exactly, and [`Self::as_str`] returns the matching label.
///
/// Invalid transitions are caught by the transition predicates
/// ([`Self::can_burn_from`], [`Self::can_wipe_from`], [`Self::can_diagnose_from`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardLifecycleState {
    /// Factory keys (all-zero K0), no SDM, empty NDEF.
    Blank,
    /// SDM active, NDEF has content, keys are derived.
    Provisioned,
    /// Mixed state: SDM configured but NDEF invalid, or vice versa.
    HalfWiped,
    /// Auth delay active (SeqFailCtr >= 50). Transient — clears on successful auth.
    AuthDelay,
    /// Signals don't match any known state.
    Inconsistent,
}

impl CardLifecycleState {
    /// Whether a burn operation can start from this state.
    pub fn can_burn_from(self) -> bool {
        matches!(self, Self::Blank | Self::Provisioned)
    }

    /// Whether a wipe operation can start from this state.
    /// Wipe requires authenticated K0 access — only possible from Provisioned.
    pub fn can_wipe_from(self) -> bool {
        matches!(self, Self::Provisioned)
    }

    /// Whether diagnose is meaningful (always true except Inconsistent).
    pub fn can_diagnose_from(self) -> bool {
        !matches!(self, Self::Inconsistent)
    }

    /// Human-readable label matching the existing classify_card_state output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blank => "BLANK",
            Self::Provisioned => "PROVISIONED",
            Self::HalfWiped => "HALF-WIPED",
            Self::AuthDelay => "AUTH_DELAY",
            Self::Inconsistent => "INCONSISTENT",
        }
    }

    /// Classify from raw signals (same logic as diagnose::classify_card_state).
    ///
    /// Precedence mirrors `classify_card_state` exactly: auth_delay dominates,
    /// then SDM+NDEF content, then the factory-auth disambiguator for the
    /// no-SDM/no-NDEF case, finally HalfWiped for any mixed combination.
    /// Factory auth does NOT override SDM/NDEF signals — a half-wiped card
    /// whose factory K0 happens to work is still HalfWiped, not Blank.
    pub fn from_signals(
        auth_delay: bool,
        has_sdm: bool,
        has_ndef: bool,
        factory_auth: bool,
    ) -> Self {
        if auth_delay {
            return Self::AuthDelay;
        }
        if has_sdm && has_ndef {
            Self::Provisioned
        } else if !has_sdm && !has_ndef {
            if factory_auth {
                Self::Blank
            } else {
                Self::Inconsistent
            }
        } else {
            Self::HalfWiped
        }
    }
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
            // Constant-time comparison to prevent timing attacks.
            // SAFETY: i ranges over 0..7 and both arrays are [u8; 7].
            #[allow(clippy::indexing_slicing)]
            {
                let mut result: u8 = 0;
                for i in 0..7 {
                    result |= stored_uid[i] ^ uid[i];
                }
                result == 0
            }
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

    // ── CardLifecycleState: signal classification ───────────────────

    #[test]
    fn state_from_signals_matches_classify_card_state() {
        assert_eq!(
            CardLifecycleState::from_signals(false, false, false, true).as_str(),
            "BLANK"
        );
        assert_eq!(
            CardLifecycleState::from_signals(false, true, true, false).as_str(),
            "PROVISIONED"
        );
        assert_eq!(
            CardLifecycleState::from_signals(true, true, true, true).as_str(),
            "AUTH_DELAY"
        );
        assert_eq!(
            CardLifecycleState::from_signals(false, false, false, false).as_str(),
            "INCONSISTENT"
        );
    }

    #[test]
    fn state_signals_dominate_factory_auth() {
        // Pins the precedence rule: SDM/NDEF signals dominate factory_auth.
        // Mirrors diagnose::security_tests::half_wiped_with_factory_auth_still_half_wiped
        // and the provisioned-with-factory-auth case.
        assert_eq!(
            CardLifecycleState::from_signals(false, true, false, true),
            CardLifecycleState::HalfWiped
        );
        assert_eq!(
            CardLifecycleState::from_signals(false, false, true, true),
            CardLifecycleState::HalfWiped
        );
        assert_eq!(
            CardLifecycleState::from_signals(false, true, true, true),
            CardLifecycleState::Provisioned
        );
    }

    #[test]
    fn state_auth_delay_overrides_everything() {
        assert_eq!(
            CardLifecycleState::from_signals(true, false, false, false),
            CardLifecycleState::AuthDelay
        );
        assert_eq!(
            CardLifecycleState::from_signals(true, true, true, true),
            CardLifecycleState::AuthDelay
        );
    }

    // ── CardLifecycleState: transition predicates ───────────────────

    #[test]
    fn burn_only_from_blank_or_provisioned() {
        assert!(CardLifecycleState::Blank.can_burn_from());
        assert!(CardLifecycleState::Provisioned.can_burn_from());
        assert!(!CardLifecycleState::HalfWiped.can_burn_from());
        assert!(!CardLifecycleState::AuthDelay.can_burn_from());
        assert!(!CardLifecycleState::Inconsistent.can_burn_from());
    }

    #[test]
    fn wipe_only_from_provisioned() {
        assert!(!CardLifecycleState::Blank.can_wipe_from());
        assert!(CardLifecycleState::Provisioned.can_wipe_from());
        assert!(!CardLifecycleState::HalfWiped.can_wipe_from());
        assert!(!CardLifecycleState::AuthDelay.can_wipe_from());
        assert!(!CardLifecycleState::Inconsistent.can_wipe_from());
    }

    #[test]
    fn diagnose_meaningful_except_inconsistent() {
        assert!(CardLifecycleState::Blank.can_diagnose_from());
        assert!(CardLifecycleState::Provisioned.can_diagnose_from());
        assert!(CardLifecycleState::HalfWiped.can_diagnose_from());
        assert!(CardLifecycleState::AuthDelay.can_diagnose_from());
        assert!(!CardLifecycleState::Inconsistent.can_diagnose_from());
    }

    #[test]
    fn as_str_returns_expected_labels() {
        assert_eq!(CardLifecycleState::Blank.as_str(), "BLANK");
        assert_eq!(CardLifecycleState::Provisioned.as_str(), "PROVISIONED");
        assert_eq!(CardLifecycleState::HalfWiped.as_str(), "HALF-WIPED");
        assert_eq!(CardLifecycleState::AuthDelay.as_str(), "AUTH_DELAY");
        assert_eq!(CardLifecycleState::Inconsistent.as_str(), "INCONSISTENT");
    }
}
