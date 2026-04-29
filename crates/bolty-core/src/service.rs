use crate::{
    assessment::CardAssessment,
    config::{LnurlString, MessageString},
    secret::CardKeys,
};

/// Result of a card workflow operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum WorkflowResult {
    Success,
    CardNotPresent,
    AuthFailed,
    AuthDelay,
    WipeRefused,
    Error(MessageString),
}

/// The shared service layer. Serial, REST, GUI, and OTA all call this.
/// Implementors provide the card I/O; bolty-core provides the policy.
pub trait BoltyService {
    fn burn(&mut self, keys: &CardKeys, lnurl: &str) -> WorkflowResult;
    fn wipe(&mut self, expected_keys: Option<&CardKeys>) -> WorkflowResult;
    #[allow(clippy::result_large_err)]
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
