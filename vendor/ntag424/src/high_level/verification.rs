use alloc::{string::String, vec::Vec};
use core::{error::Error, fmt::Debug};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    KeyNumber, TagTamperStatusReadout, crypto::originality::OriginalitySignature,
    key_diversification::diversify_ntag424, sdm::Verifier, types::FileSettingsError,
};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerificationError<E: Error + Debug> {
    #[error("tag validation failed: {0}")]
    TagValidationFailed(#[from] FileSettingsError),
    #[error("verifier error: {0}")]
    SdmError(#[from] crate::sdm::SdmError),
    #[error("verification store error: {0}")]
    StoreError(E),
    #[error("read counter is not greater than stored: stored {stored}, got {actual}")]
    ReadCounterTooLow { stored: u32, actual: u32 },
    #[error("input does not contain a UID")]
    NoUid,
    #[error("input prefix does not match expected prefix")]
    PrefixMismatch,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// Record produced by the [`provision`](super::provision) family of functions.
///
/// Bundles everything needed to verify future SDM-signed reads from the tag,
/// along with the tag's permanent UID and its NXP originality signature as
/// proof of authenticity.
///
/// The verification environment needs to be able to identify the correct
/// `ApplicationVerifier` without access to the UID (which is encrypted in
/// the URL). Add a small version or application identifier to the URL to
/// enable routing.
pub struct ApplicationVerifier {
    pub url_template: String,
    pub verifier: Verifier,
    pub prefix: Option<Vec<u8>>,
    pub system_identifier: Vec<u8>,
    /// The tag's permanent 7-byte UID, if known (set by the `provision` family of functions).
    pub uid: Option<[u8; 7]>,
    /// The NXP originality signature verified during provisioning, if available.
    pub originality_signature: Option<OriginalitySignature>,
}

/// A store for read counters.
pub trait ReadCounterStorage {
    type Error: Error + Debug;

    /// Get the read counter for the given UID.
    fn get(&mut self, uid: &[u8; 7]) -> impl Future<Output = Result<u32, Self::Error>>;

    /// Update the read counter for the given UID.
    fn set(
        &mut self,
        uid: &[u8; 7],
        read_counter: u32,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

impl ReadCounterStorage for u32 {
    type Error = core::convert::Infallible;

    async fn get(&mut self, _uid: &[u8; 7]) -> Result<u32, Self::Error> {
        Ok(*self)
    }

    async fn set(&mut self, _uid: &[u8; 7], read_counter: u32) -> Result<(), Self::Error> {
        *self = read_counter;
        Ok(())
    }
}

/// The data recovered from a successfully verified tag readout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTagReadout {
    /// The tag's real UID, recovered from PICCData.
    pub uid: [u8; 7],
    /// The tag's monotonically increasing read counter, if the SDM mirror
    /// included it. After a successful [`ApplicationVerifier::verify`] call this value has been
    /// stored as the new high-water mark in the [`ReadCounterStorage`].
    pub read_ctr: Option<u32>,
    /// The tag-tamper status reported by the tag, if the SDM mirror
    /// included it. Inspect [`TagTamperStatusReadout::is_tampered`] to
    /// decide whether to treat the readout as suspect.
    pub tamper_status: Option<TagTamperStatusReadout>,
}

impl ApplicationVerifier {
    /// Verify a tag readout produced by an SDM URL tap.
    ///
    /// Performs, in order:
    ///
    /// 1. **Prefix check** — if this `ApplicationVerifier` carries a `prefix`,
    ///    `input` must begin with it; the prefix is **not** stripped, since
    ///    verifier byte ranges are computed over the full input.
    /// 2. **Verifier consistency check** — guards against an
    ///    `ApplicationVerifier` that was deserialized from an inconsistent
    ///    source.
    /// 3. **PICC decryption** — recovers the UID (and read counter, if mirrored)
    ///    using the cohort-fixed `SDMMetaRead` key derived from `master_key`.
    ///    This step matches the [`provision`](super::provision) family, which
    ///    always assigns `KeyNumber::Key1` to `SDMMetaRead` and derives that
    ///    key as a cohort-fixed value bound to `master_key`.
    /// 4. **MAC verification** — derives the per-tag `SDMFileRead` key from
    ///    `master_key`, the UID, and the application's `system_identifier`,
    ///    then verifies the SDMMAC over the readout. A failure here means the
    ///    URL is forged or corrupted; this method returns
    ///    [`VerificationError::SdmError`].
    /// 5. **Replay check** — if the readout includes a read counter, it is
    ///    compared against the value in `read_counter` for this UID. The new
    ///    counter must be strictly greater than the stored one; otherwise
    ///    [`VerificationError::ReadCounterTooLow`] is returned. On success the
    ///    new counter is written back before this method returns.
    ///
    /// On success, the returned [`VerifiedTagReadout`] surfaces the UID, the
    /// new read counter (if mirrored), and the tag-tamper status (if mirrored).
    /// The caller is responsible for inspecting
    /// [`tamper_status`](VerifiedTagReadout::tamper_status); this method does
    /// not reject tampered tags on its own, since some deployments still want
    /// to honor the tap and only flag the tamper event.
    ///
    /// # Limitations
    ///
    /// This method assumes the tag was provisioned by [`provision`](super::provision)
    /// (or by [`provision_with_keys`](super::provision_with_keys) /
    /// [`provision_with_fn`](super::provision_with_fn) with keys derived via
    /// [`derive_keys_for_uid`](super::derive_keys_for_uid)). Specifically, it
    /// assumes `SDMMetaRead` is keyed by the cohort PICC key
    /// (`picc_key(master_key)`) and every other application key is per-tag
    /// diversified with [`diversify_ntag424`]. Tags provisioned with arbitrary
    /// custom key material will not verify here; use the lower-level
    /// [`Verifier`] API directly.
    pub async fn verify<S: ReadCounterStorage>(
        &self,
        master_key: &[u8; 16],
        input: &[u8],
        read_counter: &mut S,
    ) -> Result<VerifiedTagReadout, VerificationError<S::Error>> {
        // If a prefix is configured, check that the input starts with it, but do not strip it,
        // verifier ranges are computed over the full input (including the prefix)
        if let Some(prefix) = &self.prefix
            && !input.starts_with(prefix.as_slice())
        {
            return Err(VerificationError::PrefixMismatch);
        }

        // Check verifier consistency
        self.verifier.validate()?;

        // The cohort-fixed SDMMetaRead key (Key1 in the high-level provisioning).
        // Used to decrypt PICCData, which is the only step that runs before we
        // know the UID — hence cohort-fixed rather than per-tag.
        let picc_meta_key = super::picc_key(master_key);
        let (uid, _) = self.verifier.decrypt_picc_data(&picc_meta_key, input)?;
        let Some(uid) = uid else {
            return Err(VerificationError::NoUid);
        };

        // Now that the UID is known, derive the per-tag SDMFileRead key
        // (Key2 in the high-level provisioning) and verify the MAC.
        let file_read_key = get_key(
            master_key,
            self.verifier.file_read_key(),
            &uid,
            &self.system_identifier,
        );
        let verification =
            self.verifier
                .verify_with_meta_key(input, &file_read_key, &picc_meta_key)?;

        if let Some(counter) = verification.read_ctr {
            let stored = read_counter
                .get(&uid)
                .await
                .map_err(VerificationError::StoreError)?;
            if counter <= stored {
                return Err(VerificationError::ReadCounterTooLow {
                    stored,
                    actual: counter,
                });
            }
            read_counter
                .set(&uid, counter)
                .await
                .map_err(VerificationError::StoreError)?;
        }

        Ok(VerifiedTagReadout {
            uid,
            read_ctr: verification.read_ctr,
            tamper_status: verification.tamper_status,
        })
    }
}

fn get_key(
    master_key: &[u8; 16],
    key_number: KeyNumber,
    uid: &[u8; 7],
    system_identifier: &[u8],
) -> [u8; 16] {
    match key_number {
        KeyNumber::Key1 => super::picc_key(master_key),
        k @ (KeyNumber::Key0 | KeyNumber::Key2 | KeyNumber::Key3 | KeyNumber::Key4) => {
            diversify_ntag424(master_key, uid, k, system_identifier)
        }
    }
}
