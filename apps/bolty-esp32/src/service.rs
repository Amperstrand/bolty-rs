use bolty_core::{
    assessment::CardAssessment,
    config::{ErrorString, LnurlString},
    secret::{AesKey, CardKeys},
};

/// Result of a card workflow operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowResult {
    Success,
    CardNotPresent,
    AuthFailed,
    AuthDelay,
    WipeRefused,
    Error(ErrorString),
}

/// The shared service layer. Serial, REST, GUI, and OTA all call this.
/// Implementors provide the card I/O; bolty-core provides the policy.
pub trait BoltyService {
    fn burn(
        &mut self,
        issuer: Option<&AesKey>,
        keys: Option<&CardKeys>,
        lnurl: &str,
    ) -> WorkflowResult;
    fn wipe(&mut self, issuer: Option<&AesKey>, keys: Option<&CardKeys>) -> WorkflowResult;
    fn inspect(&mut self) -> Result<CardAssessment, WorkflowResult>;
    fn check_blank(&mut self) -> WorkflowResult;
    fn get_status(&self) -> ServiceStatus;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub last_uid: Option<[u8; 7]>,
    pub nfc_ready: bool,
    pub lnurl: Option<LnurlString>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_default() {
        let status = ServiceStatus::default();
        assert!(status.last_uid.is_none());
        assert!(!status.nfc_ready);
        assert!(status.lnurl.is_none());
    }

    #[test]
    fn workflow_result_success_eq() {
        assert_eq!(WorkflowResult::Success, WorkflowResult::Success);
        assert_ne!(WorkflowResult::Success, WorkflowResult::CardNotPresent);
    }

    #[test]
    fn workflow_result_error_with_message() {
        let mut msg = ErrorString::new();
        let _ = msg.push_str("card error");
        let result = WorkflowResult::Error(msg);
        assert!(matches!(result, WorkflowResult::Error(_)));
    }

    #[test]
    fn workflow_result_clone() {
        let result = WorkflowResult::AuthFailed;
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn workflow_result_all_variants_neq() {
        let variants = [
            WorkflowResult::Success,
            WorkflowResult::CardNotPresent,
            WorkflowResult::AuthFailed,
            WorkflowResult::AuthDelay,
            WorkflowResult::WipeRefused,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} should differ");
                }
            }
        }
    }
}
