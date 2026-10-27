use core::fmt::Debug;
use core::{convert::Infallible, error::Error};

use alloc::borrow::ToOwned;
use rand::CryptoRng;

use super::{ApplicationVerifier, picc_key};
use crate::TagTamperStatusReadout;
use crate::crypto::originality::OriginalitySignature;
use crate::sdm::SdmUrlConfig;
use crate::types::file_settings::Sdm;
use crate::{
    Access, AccessRights, AuthenticatedSession, CommMode, Configuration, EncryptedSession, File,
    FileSettingsUpdate, KeyNumber, NonMasterKeyNumber, Session, SessionError, Transport, Version,
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, Verifier, sdm_url_config},
    types::file_settings::CryptoMode,
};

const SYSTEM_IDENTIFIER: &[u8] = b"NTAG424DNA";
const MODE: CryptoMode = CryptoMode::Lrp;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProvisioningError<E: Error + Debug, K: Error + Debug> {
    #[error("PICC data does not contain a UID")]
    NoUid,
    #[error("verification error: {0}")]
    SdmError(#[from] crate::sdm::SdmError),
    #[error("sdm url error: {0}")]
    SdmUrlError(#[from] crate::sdm::SdmUrlError),
    #[error("session error: {0}")]
    SessionError(#[from] SessionError<E>),
    #[error("tag version mismatch: expected NTAG 424 DNA, got hardware type {hw_type:#04x}")]
    VersionMismatch { hw_type: u8 },
    #[error("tag is tampered ({0:?})")]
    Tampered(TagTamperStatusReadout),
    #[error("SDM verifier offset adjustment out of range; check URL length")]
    Offset,
    #[error("SDM URL must include UID mirroring (e.g. {{picc}} or {{uid}}) for provisioning")]
    NoUidMirroring,
    #[error("key generation failed: {0}")]
    KeyGenerationError(K),
}

/// Provisions a new NTAG 424 DNA tag with the given master key and URL.
///
/// The tag must be in factory default state (all keys all-zero, AES mode, random UID disabled).
///
/// In detail, the provisioning process consists of the following steps:
///
/// - Checks the tag's version to ensure it is an NTAG 424 DNA.
/// - Verifies the tag's NXP originality signature.
/// - Enables LRP crypto mode and random UID mode; enables tag tamper protection if the hardware
///   supports it.
/// - Derives new AES keys for keys 1 to 4 from the master key. Key 1 is a cohort-fixed PICC
///   meta-read key; keys 2–4 are per-tag UID-diversified.
/// - Writes the NDEF URL template, configures SDM, file permissions, and all five keys.
/// - Updates the **Capability Container** (File No. `01h`) to reflect the new NDEF access
///   conditions so NFC Forum readers see an accurate T4T mapping.
/// - Changes the master key (Key 0) to a per-tag diversified value last, terminating the session.
///
/// Returns an [`ApplicationVerifier`] (which the server can use for subsequent SDM
/// verification) together with the tag's UID.
///
/// The URL pattern `url_template` must satisfy the requirements of
/// [`sdm_url_config`](`crate::sdm::sdm_url_config`). Additionally:
///
/// - The URL must include the UID, either via `{picc}` (encrypted) or `{uid}` (plain).
///   Plain `{uid}` is readable without the PICC key — prefer `{picc}` for privacy.
/// - The URL should include the read counter (`{picc}` or `{ctr}`) so the server can detect replays.
/// - The `{mac}` position should be after all other placeholders.
///
/// # URL Examples
///
/// - `https://example.com/?id={picc}{mac}`
/// - `url:nfc:{picc}{tt}{mac}` (includes tag tamper status readout, must
///   [be supported](`crate::Version::has_tag_tamper_support`) by the tag)
/// - `https://example.com/{uid}/{ctr}?mac={mac}` (UID is not encrypted!)
///
/// # Irreversible operations
///
/// <div class="warning">
///
/// This function makes **permanent, irreversible** changes to the tag:
///
/// - **LRP mode** is enabled. Once set, the tag rejects all AES-mode commands and
///   LRP mode cannot be disabled.
/// - **Random UID** is enabled. The tag will never again expose its real UID during
///   NFC anti-collision; the real UID is only recoverable via an authenticated
///   `GetCardUID` command.
///
/// Test on disposable tags before running against production stock.
///
/// </div>
///
/// # Security considerations
///
/// **Factory-state assumption** — the function authenticates with all-zero keys. If the
/// tag has already been (partially) provisioned, AES auth silently fails and the function
/// attempts LRP auth with all-zero keys; if that also fails, a generic
/// [`SessionError`](`crate::SessionError`) is returned with no indication that the tag
/// was not in factory state. Verify the tag is genuinely factory-fresh before calling.
///
/// **Master key custody** — all five application keys are deterministically derived from
/// `master_key`. Compromise of `master_key` exposes every tag provisioned with it and
/// makes all historical SDM taps decryptable. Store `master_key` in a hardware security
/// module or equivalent; never log or persist it in plaintext.
///
/// **PICC key scope** — Key 1 is cohort-fixed (identical on every tag provisioned with
/// the same `master_key`). If Key 1 is extracted from any tag in the fleet, an attacker
/// can decrypt the PICC data (UID + counter) from every other tag. MAC verification
/// (Key 2, per-tag diversified) is not affected.
///
/// **System identifier** — all tags provisioned by this function share the fixed system
/// identifier `"NTAG424DNA"`. Two independent deployments using the same `master_key`
/// against the same physical tag would derive identical application keys. If you need
/// key-space isolation across deployments, use the lower-level API with a deployment-specific
/// system identifier.
///
/// **File write access** — the NDEF file is configured with `ReadWrite` access requiring
/// Key 0 (the master key). Updating the NDEF content later therefore requires the master
/// key on-site. If that is too privileged for your update workflow, use the lower-level API
/// and assign a less-privileged key to `ReadWrite`.
///
/// **Partial failure** — if provisioning is interrupted after some keys have been changed,
/// the tag is left in a mixed state. Recovery requires re-authenticating with the then-current
/// master key (Key 0 stays factory-zero until the final step) and completing the remaining
/// `change_key` calls manually. There is no automatic rollback.
pub async fn provision<T: Transport>(
    transport: &mut T,
    url_template: &str,
    master_key: &[u8; 16],
    rng: &mut impl CryptoRng,
) -> Result<ApplicationVerifier, ProvisioningError<T::Error, Infallible>> {
    let key_fn = |uid| {
        let new_keys = derive_keys_for_uid(master_key, &uid);
        core::future::ready(Ok(new_keys))
    };
    provision_with_fn(transport, url_template, key_fn, rng).await
}

/// Derives the five AES keys for a tag from the master key and UID.
pub fn derive_keys_for_uid(master_key: &[u8; 16], uid: &[u8; 7]) -> [[u8; 16]; 5] {
    // Key1 holds the cohort-fixed PICC encryption key (it must be the same on every tag,
    // so the server can decrypt PICC data before knowing the UID). Key2..Key4 are per-tag
    // diversified.
    let key1 = picc_key(master_key);
    let new_master_key = diversify_ntag424(master_key, uid, KeyNumber::Key0, SYSTEM_IDENTIFIER);
    [
        new_master_key,
        key1,
        diversify_ntag424(master_key, uid, KeyNumber::Key2, SYSTEM_IDENTIFIER),
        diversify_ntag424(master_key, uid, KeyNumber::Key3, SYSTEM_IDENTIFIER),
        diversify_ntag424(master_key, uid, KeyNumber::Key4, SYSTEM_IDENTIFIER),
    ]
}

/// Variant of `provision` that takes pre-derived keys directly, skipping the key diversification step.
///
/// This is useful if the master key should be kept secret from the
/// provisioning environment.
pub async fn provision_with_keys<T: Transport>(
    transport: &mut T,
    url_template: &str,
    keys: &[[u8; 16]; 5],
    rng: &mut impl CryptoRng,
) -> Result<ApplicationVerifier, ProvisioningError<T::Error, Infallible>> {
    provision_with_fn(
        transport,
        url_template,
        |_| core::future::ready(Ok(*keys)),
        rng,
    )
    .await
}

/// Core provisioning function that takes a user-supplied async function to derive the new keys from the UID.
///
/// Generalized version of [`provision`](`provision`). The keys are not
/// derived internally; instead, the caller provides an async function `keys` that takes the UID
/// and returns the new keys.
pub async fn provision_with_fn<T: Transport, F, Fut, K>(
    transport: &mut T,
    url_template: &str,
    keys: F,
    rng: &mut impl CryptoRng,
) -> Result<ApplicationVerifier, ProvisioningError<T::Error, K>>
where
    K: Error + Debug,
    F: FnOnce([u8; 7]) -> Fut,
    Fut: core::future::Future<Output = Result<[[u8; 16]; 5], K>>,
{
    // Create SDM config early so we can fail before provisioning
    let (sdm_conf, verifier) = create_sdm_url_config(url_template, MODE)?;
    if !sdm_conf.mirrors_uid() {
        return Err(ProvisioningError::NoUidMirroring);
    }
    let prefix = sdm_conf.prefix();

    let version = check_version(transport).await?;
    let session = authenticate_using_factory_defaults(transport, rng).await?;
    let (uid, session, originality_signature) = verify_originality(transport, session).await?;
    let new_keys = keys(uid)
        .await
        .map_err(ProvisioningError::KeyGenerationError)?;

    let session = configure(
        transport,
        session,
        &version,
        sdm_conf.sdm_settings.tamper_status().is_some(),
    )
    .await?;
    let session = configure_ndef(transport, session, sdm_conf).await?;

    // Update keys
    provision_keys(transport, session, &new_keys).await?;

    Ok(ApplicationVerifier {
        verifier,
        url_template: url_template.to_owned(),
        prefix: prefix.map(|p| p.to_owned()),
        system_identifier: SYSTEM_IDENTIFIER.to_vec(),
        uid: Some(uid),
        originality_signature: Some(originality_signature),
    })
}

fn create_sdm_url_config<E, K>(
    url_template: &str,
    mode: CryptoMode,
) -> Result<(SdmUrlConfig, Verifier), ProvisioningError<E, K>>
where
    E: Error + Debug,
    K: Error + Debug,
{
    let opts = SdmUrlOptions {
        picc_key: KeyNumber::Key1,
        mac_key: KeyNumber::Key2,
        ..Default::default()
    };
    let sdm_conf = sdm_url_config(url_template, mode, opts)?;
    let verifier = Verifier::try_new(&sdm_conf.sdm_settings, mode)?
        // Shift all NDEF byte offsets so the verifier operates on the full URL string
        // (prefix prepended) rather than raw NDEF bytes.
        .with_offset(sdm_conf.prefix_len as i32 - sdm_conf.offset as i32)
        .ok_or_else(|| ProvisioningError::Offset)?;
    Ok((sdm_conf, verifier))
}

/// Creates an SDM application verifier from the given URL template.
///
/// Returns the same verifier that `provision` produces alongside the UID.
pub fn create_app_verifier(
    url_template: &str,
) -> Result<super::ApplicationVerifier, ProvisioningError<Infallible, Infallible>> {
    let (sdm_conf, verifier) = create_sdm_url_config(url_template, MODE)?;
    Ok(super::ApplicationVerifier {
        verifier,
        url_template: url_template.to_owned(),
        prefix: sdm_conf.prefix().map(|p| p.to_owned()),
        system_identifier: SYSTEM_IDENTIFIER.to_vec(),
        uid: None,
        originality_signature: None,
    })
}

async fn configure_ndef<T: Transport>(
    transport: &mut T,
    mut session: EncryptedSession,
    config: crate::sdm::SdmUrlConfig,
) -> Result<EncryptedSession, SessionError<T::Error>> {
    let sdm = config.sdm_settings;

    session = session
        .write_file(transport, File::Ndef, 0, &config.ndef_bytes)
        .await?;

    session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &get_file_settings_update_for_sdm(sdm),
        )
        .await?;

    // Synchronise the Capability Container with the new NDEF access conditions.
    // Standard NFC readers consult the CC to determine whether they may read or
    // write the NDEF file; leaving it at factory defaults (write = open) after
    // provisioning would mislead them about the actual tag policy.
    // Read stays Open; write becomes ProprietaryKey(Key0) to reflect that
    // authenticated writes via Key0 are possible (read_write = Key0) while
    // unauthenticated writes are not (write = NoAccess).
    let cc_bytes = crate::types::cc::CapabilityContainer::default()
        .with_ndef_write_access(crate::types::cc::AccessCondition::ProprietaryKey(
            KeyNumber::Key0,
        ))
        .to_bytes();
    session = session
        .write_file_with_mode(
            transport,
            File::CapabilityContainer,
            0,
            &cc_bytes,
            CommMode::Plain,
        )
        .await?;

    Ok(session)
}

fn get_file_settings_update_for_sdm(sdm: Sdm) -> FileSettingsUpdate {
    FileSettingsUpdate::new(
        // Plain CommMode is required for unauthenticated reads by standard NFC readers.
        CommMode::Plain,
        AccessRights {
            // Free read is required so standard readers can fetch the SDM URL without
            // authenticating.
            read: Access::Free,
            // Write-only access disabled; authenticated read-write via Key0 is used
            // instead. Key0 (master) is intentionally required here — use the lower-level
            // API and assign a less-privileged key if field NDEF updates must avoid
            // exposing the root secret.
            write: Access::NoAccess,
            read_write: Access::Key(KeyNumber::Key0),
            change: Access::Key(KeyNumber::Key0),
        },
    )
    .with_sdm(sdm)
}

async fn provision_keys<T: Transport>(
    transport: &mut T,
    mut session: EncryptedSession,
    keys: &[[u8; 16]; 5],
) -> Result<(), SessionError<T::Error>> {
    for (new_key, key_number) in keys[1..].iter().zip([
        NonMasterKeyNumber::Key1,
        NonMasterKeyNumber::Key2,
        NonMasterKeyNumber::Key3,
        NonMasterKeyNumber::Key4,
    ]) {
        let old_key = [0u8; 16]; // factory default key
        session = session
            .change_key(transport, key_number, new_key, 0x01, &old_key)
            .await?;
    }
    session.change_master_key(transport, &keys[0], 0x01).await?;
    Ok(())
}

async fn configure<T: Transport, K: Error + Debug>(
    transport: &mut T,
    session: EncryptedSession,
    version: &Version,
    enable_tag_tamper: bool,
) -> Result<EncryptedSession, ProvisioningError<T::Error, K>> {
    let mut config = Configuration::new().with_random_uid_enabled();
    let tag_tamper_enabled = if version.has_tag_tamper_support() && enable_tag_tamper {
        // Free access lets the tag mirror tamper status into the SDM URL without
        // requiring authentication, suitable for "package seal" use cases where any
        // reader should be able to check integrity. Use the lower-level API if you
        // need tamper status gated behind a key.
        config = config.with_tag_tamper_enabled(Access::Free);
        true
    } else {
        false
    };
    let mut session = session.set_configuration(transport, &config).await?;
    if tag_tamper_enabled {
        let (tt_status, new_session) = session.get_tt_status(transport).await?;
        if tt_status.is_tampered() {
            return Err(ProvisioningError::Tampered(tt_status));
        }
        session = new_session;
    }
    Ok(session)
}

async fn verify_originality<T: Transport>(
    transport: &mut T,
    session: EncryptedSession,
) -> Result<([u8; 7], EncryptedSession, OriginalitySignature), SessionError<T::Error>> {
    let (uid, session) = session.get_uid(transport).await?;
    let (session, sig) = session.verify_originality(transport, &uid).await?;
    Ok((uid, session, sig))
}

async fn check_version<T: Transport, K: Error + Debug>(
    transport: &mut T,
) -> Result<Version, ProvisioningError<T::Error, K>> {
    let version = Session::new().get_version(transport).await?;
    if version.hw_type() != 0x04 {
        return Err(ProvisioningError::VersionMismatch {
            hw_type: version.hw_type(),
        });
    }
    Ok(version)
}

/// Authenticate with the factory-default all-zero master key and switch to LRP mode.
///
/// Attempts AES auth first (factory mode); if the tag is already in LRP mode, AES auth
/// will be rejected and the function falls through directly to LRP auth. If both attempts
/// fail — because the master key is no longer all-zero — a generic
/// [`SessionError`](`crate::SessionError`) is returned with no indication that the tag
/// was not in factory state.
async fn authenticate_using_factory_defaults<T: Transport>(
    transport: &mut T,
    rng: &mut impl CryptoRng,
) -> Result<EncryptedSession, SessionError<T::Error>> {
    use rand::RngExt as _;

    if let Ok(s) = Session::new()
        .authenticate_aes(transport, KeyNumber::Key0, &[0; 16], rng.random())
        .await
    {
        if MODE == CryptoMode::Lrp {
            s.enable_lrp(transport).await?;
        } else {
            return Ok(s.into());
        }
    }
    Session::new()
        .authenticate_lrp(transport, KeyNumber::Key0, &[0; 16], rng.random())
        .await
        .map(EncryptedSession::from)
}
