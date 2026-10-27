//! High-level, opinionated API for provisioning and using the NTAG 424 DNA.
//!
//! This module provides convenient abstractions for common operations:
//!
//! - **Provisioning**: Configure a tag with keys, NDEF content, and SDM settings
//! - **Verification**: Verify SDM-signed tag reads using [`ApplicationVerifier::verify`]
//! - **Reset**: Restore a provisioned tag toward factory-default state using [`reset`]
//!
//! The implementation is opinionated in the sense that it choses a secret key strategey,
//! SDM settings, and general tag settings. The chosen approach puts focus on
//! privacy and security. The details are documented in the respective functions.
//!
//! The high-level API handles low-level protocol details, enabling you to work with
//! higher-level concepts like URL templates, key derivation, and tag information storage.
//!
//! # Example: Provisioning a tag
//!
//! ```no_run
//! # use ntag424::Transport;
//! use ntag424::high_level::{provision, ApplicationVerifier};
//! # #[cfg(all(feature = "high-level-api", feature = "rand/sys_rng"))]
//! # async fn provision_example(transport: &mut impl Transport) -> Result<(), Box<dyn std::error::Error>> {
//! use rand::{make_rng, rngs::SysRng};
//!
//! # let master_key = [0u8; 16];
//! // let master_key: [u8; 16] = ...;
//! let url_template = "https://example.com/?p={picc}&m={mac}";
//! let mut rng: SysRng = make_rng();
//!
//! let app_verifier: ApplicationVerifier =
//!     provision(transport, url_template, &master_key, &mut rng)
//!         .await
//!         .expect("Provisioning failed");
//!
//! // Store app_verifier for later verification; it contains the UID and originality signature
//! # Ok(())
//! # }
//! ```
//! # Example: Verifying a tag read
//!
//! The high-level verification API uses an [`ApplicationVerifier`] to check
//! SDM-signed NDEF data from tag reads. The replay protection mechanism
//! requires to store a read counter per tag UID which must be provided using
//! a [`ReadCounterStorage`] implementation.
//!
//! ```
//! # use ntag424::high_level::{ApplicationVerifier, VerifiedTagReadout, ReadCounterStorage};
//! # #[cfg(feature = "high-level-api")]
//! # async fn verify_example(app_verifier: ApplicationVerifier, mut counter_storage: impl ReadCounterStorage) {
//! # let master_key = &[0u8; 16];
//! // let master_key: &[u8; 16] = ...;
//! let input = b"https://example.com/v1/?p=...&m=...";  // the decoded NDEF read from the tag
//! // let app_verifier: ApplicationVerifier = ...;  // obtained from storage, maybe using version/app identifier in input
//! // let mut counter_storage = ...;  // your implementation of ReadCounterStorage
//!
//! let result = app_verifier.verify(master_key, input, &mut counter_storage).await;
//! # }
//! ```
use crate::key_diversification::diversify_aes128;

mod provision;
mod reset;
mod verification;

pub use provision::{
    ProvisioningError, create_app_verifier, derive_keys_for_uid, provision, provision_with_fn,
    provision_with_keys,
};
pub use reset::{ResetError, reset, reset_with_fn, reset_with_keys};
pub use verification::{
    ApplicationVerifier, ReadCounterStorage, VerificationError, VerifiedTagReadout,
};

/// Derives the cohort-fixed PICC encryption key (SDMMetaRead, Key 1).
pub fn picc_key(master: &[u8; 16]) -> [u8; 16] {
    // Domain-separated from [`diversify_ntag424`] outputs: `b"PICC"` begins with byte
    // `0x50`, whereas `diversify_ntag424` inputs always start with a key-number byte in
    // `0x00..=0x04`, so the two derivation paths can never collide.
    diversify_aes128(master, b"PICC")
}
