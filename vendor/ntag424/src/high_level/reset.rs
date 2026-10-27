use core::convert::Infallible;
use core::error::Error;
use core::fmt::Debug;

use rand::{CryptoRng, RngExt as _};

use super::{derive_keys_for_uid, picc_key};
use crate::{
    AuthenticatedSession as _, CommMode, EncryptedSession, File, FileSettingsView, KeyNumber,
    NonMasterKeyNumber, Session, SessionError, Transport, types::cc::CapabilityContainer,
};

/// Error type for the `reset` family of functions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResetError<E: Error + Debug, K: Error + Debug = Infallible> {
    #[error("session error: {0}")]
    SessionError(#[from] SessionError<E>),
    #[error("key generation failed: {0}")]
    KeyGenerationError(K),
}

/// Resets a provisioned tag back toward factory-default state.
///
/// Derives the five application keys from `master_key` and the tag's UID,
/// authenticates with the current master key (Key 0), then reverses the
/// changes made by [`provision`](`crate::high_level::provision`):
///
/// - Resets NDEF and Capability Container file settings to factory defaults
///   (removes SDM configuration and restores access rights).
/// - Writes the factory-default Capability Container content.
/// - Zeroes the NDEF file.
/// - Resets keys 1–4 to the all-zero factory default.
/// - Resets the master key (Key 0) to the all-zero factory default last.
///
/// Returns the UID used for the reset — which equals `uid` when supplied, or
/// the UID retrieved from the tag via Key 1 authentication otherwise.
///
/// Authentication tries LRP first; if that fails (e.g. provisioning was
/// interrupted before LRP mode was enabled), it falls back to AES with the
/// same derived key.
///
/// # Retrieving the UID
///
/// When `uid` is `None` the function authenticates with Key 1 (the
/// cohort-fixed PICC meta-read key derived from `master_key`) to retrieve the
/// real UID from the tag via `GetCardUID`.  Provide `uid` directly if you
/// already know it, to avoid the extra round-trip.
///
/// # Irreversible state
///
/// LRP mode, random UID mode, and tag tamper protection (if it was enabled
/// during provisioning) cannot be disabled.  After a successful reset the tag
/// passes factory-state checks for keys and file settings, but those bits
/// remain set permanently.
/// Use [`Session::check_factory_state`](`crate::Session::check_factory_state`)
/// to verify the result.
///
/// # Partial failure
///
/// If the reset is interrupted after some non-master keys have been zeroed
/// but before the master key is reset, the tag is in a partially-reset state.
/// Calling this function again with the same `master_key` and `uid` is safe:
/// all completed steps are idempotent.  Key 0 is reset last, so the current
/// master key remains valid for re-authentication until that final step.
pub async fn reset<T: Transport>(
    transport: &mut T,
    master_key: &[u8; 16],
    uid: Option<[u8; 7]>,
    rng: &mut impl CryptoRng,
) -> Result<[u8; 7], ResetError<T::Error>> {
    let uid = resolve_uid(transport, master_key, uid, rng).await?;
    reset_with_fn(
        transport,
        uid,
        |uid| core::future::ready(Ok(derive_keys_for_uid(master_key, &uid))),
        rng,
    )
    .await?;
    Ok(uid)
}

/// Variant of [`reset`] that takes pre-derived keys directly.
///
/// Useful when the master key must be kept out of the resetting environment:
/// derive the five keys externally (e.g. in an HSM), pass them in, and this
/// function performs the reset without ever seeing `master_key`.
///
/// `uid` must be the tag's permanent real UID (7 bytes).  Use [`reset`] if
/// you need automatic UID retrieval via Key 1 authentication.
pub async fn reset_with_keys<T: Transport>(
    transport: &mut T,
    uid: [u8; 7],
    keys: &[[u8; 16]; 5],
    rng: &mut impl CryptoRng,
) -> Result<(), ResetError<T::Error>> {
    reset_with_fn(transport, uid, |_| core::future::ready(Ok(*keys)), rng).await
}

/// Core reset function that accepts an async key-derivation closure.
///
/// Generalized version of [`reset`].  The caller supplies an async function
/// `keys` that receives the tag's UID and returns the five current application
/// keys as `[[u8; 16]; 5]`, where index 0 is Key 0 (master key) and indices
/// 1–4 are Keys 1–4.  This is the building block for HSM-backed or otherwise
/// custom key-derivation workflows.
///
/// Authentication tries LRP first; if that fails it falls back to AES with
/// the same key, to handle tags that were partially provisioned before LRP
/// mode was enabled.
///
/// `uid` must be the tag's permanent real UID (7 bytes).  Use [`reset`] if
/// you need automatic UID retrieval via Key 1 authentication.
///
/// Returns `Ok(())` on success; the UID is not returned since the caller
/// already provides it.
///
/// # Proprietary file
///
/// The proprietary file (File 3) is not modified.
/// [`provision`](`crate::high_level::provision`) does not write to it, so a
/// reset after a full provision leaves the proprietary file in its factory
/// state.  If the proprietary file was written to independently,
/// [`Session::check_factory_state`](`crate::Session::check_factory_state`)
/// will report a mismatch until it is restored via the lower-level API.
///
/// # Partial failure
///
/// If the reset is interrupted after some non-master keys have been zeroed
/// but before the master key is reset, the tag is in a partially-reset state.
/// Calling this function again with the same keys is safe: all completed steps
/// are idempotent (file settings are written unconditionally; a key that
/// already equals zero can be changed to zero again).  Key 0 is reset last,
/// so the current master key remains valid for re-authentication until that
/// final step.
pub async fn reset_with_fn<T: Transport, F, Fut, K>(
    transport: &mut T,
    uid: [u8; 7],
    keys: F,
    rng: &mut impl CryptoRng,
) -> Result<(), ResetError<T::Error, K>>
where
    K: Error + Debug,
    F: FnOnce([u8; 7]) -> Fut,
    Fut: core::future::Future<Output = Result<[[u8; 16]; 5], K>>,
{
    let current_keys = keys(uid).await.map_err(ResetError::KeyGenerationError)?;

    let mut session: EncryptedSession = match Session::new()
        .authenticate_lrp(transport, KeyNumber::Key0, &current_keys[0], rng.random())
        .await
    {
        Ok(s) => s.into(),
        Err(_) => Session::new()
            .authenticate_aes(transport, KeyNumber::Key0, &current_keys[0], rng.random())
            .await?
            .into(),
    };

    session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &FileSettingsView::factory(File::Ndef).into_update(),
        )
        .await?;

    session = session
        .change_file_settings(
            transport,
            File::CapabilityContainer,
            &FileSettingsView::factory(File::CapabilityContainer).into_update(),
        )
        .await?;

    let cc_bytes = CapabilityContainer::default().to_bytes();
    session = session
        .write_file_with_mode(
            transport,
            File::CapabilityContainer,
            0,
            &cc_bytes,
            CommMode::Plain,
        )
        .await?;

    let ndef_zeros = [0u8; 256];
    session = session
        .write_file_with_mode(transport, File::Ndef, 0, &ndef_zeros, CommMode::Plain)
        .await?;

    for (key_no, old_key) in [
        (NonMasterKeyNumber::Key1, current_keys[1]),
        (NonMasterKeyNumber::Key2, current_keys[2]),
        (NonMasterKeyNumber::Key3, current_keys[3]),
        (NonMasterKeyNumber::Key4, current_keys[4]),
    ] {
        session = session
            .change_key(transport, key_no, &[0u8; 16], 0x00, &old_key)
            .await?;
    }

    session
        .change_master_key(transport, &[0u8; 16], 0x00)
        .await?;

    Ok(())
}

async fn resolve_uid<T: Transport>(
    transport: &mut T,
    master_key: &[u8; 16],
    uid: Option<[u8; 7]>,
    rng: &mut impl CryptoRng,
) -> Result<[u8; 7], SessionError<T::Error>> {
    match uid {
        Some(uid) => Ok(uid),
        None => {
            let key1 = picc_key(master_key);
            let session = Session::new()
                .authenticate_lrp(transport, KeyNumber::Key1, &key1, rng.random())
                .await?;
            let (uid, _) = session.get_uid(transport).await?;
            Ok(uid)
        }
    }
}
