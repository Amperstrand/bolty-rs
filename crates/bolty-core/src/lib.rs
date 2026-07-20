//! Core domain logic for Bolt Card operations.
//!
//! Provides key derivation strategies (`derivation`), PICC URL decrypt/verify
//! (`picc`), card state assessment (`assessment`), issuer registry lookup
//! (`issuer`), configuration types (`config`), and UID handling (`uid`).
//!
//! `#![no_std]`-compatible with optional `alloc` and `std` features.
//!
//! Key types: `CardAssessment`, `DerivationStrategy`, `CardKeys`, `PiccData`,
//! `BoltyConfig`, `IssuerRegistry`.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(any(feature = "alloc", feature = "std"))]
pub extern crate alloc;

pub mod assessment;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod derivation;
pub mod issuer;
pub mod picc;
pub mod provenance;
pub mod secret;
pub mod uid;
pub mod util;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_types_compile() {
        let assessment = assessment::CardAssessment::default();
        assert_eq!(assessment.kind, assessment::IdleCardKind::Unknown);

        let strategy = derivation::DerivationStrategy::default();
        assert_eq!(
            strategy,
            derivation::DerivationStrategy::BoltcardDeterministic
        );
    }
}
