#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

pub mod assessment;
pub mod commands;
pub mod config;
pub mod constants;
pub mod derivation;
pub mod issuer;
pub mod picc;
pub mod secret;
pub mod service;
pub mod workflow;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::BoltyService;

    struct DummyService;

    impl service::BoltyService for DummyService {
        fn burn(
            &mut self,
            _keys: &secret::CardKeys,
            _lnurl: &str,
        ) -> service::WorkflowResult {
            service::WorkflowResult::Success
        }

        fn wipe(&mut self, _expected_keys: Option<&secret::CardKeys>) -> service::WorkflowResult {
            service::WorkflowResult::Success
        }

        fn inspect(&mut self) -> Result<assessment::CardAssessment, service::WorkflowResult> {
            Ok(assessment::CardAssessment::default())
        }

        fn check_blank(&mut self) -> service::WorkflowResult {
            service::WorkflowResult::Success
        }

        fn get_status(&self) -> service::ServiceStatus {
            service::ServiceStatus::default()
        }
    }

    #[test]
    fn service_api_compiles() {
        let assessment = assessment::CardAssessment::default();
        assert_eq!(assessment.kind, assessment::IdleCardKind::Unknown);

        let strategy = derivation::DerivationStrategy::default();
        assert_eq!(
            strategy,
            derivation::DerivationStrategy::BoltcardDeterministic
        );

        let mut service = DummyService;
        assert!(matches!(service.check_blank(), service::WorkflowResult::Success));
    }
}
