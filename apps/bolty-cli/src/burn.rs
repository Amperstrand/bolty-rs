use anyhow::Context;
use bolty_core::derivation::{BoltcardDeterministicDeriver, CardKeySet};
use ntag424::{
    AuthenticatedSession, File, KeyNumber, NonMasterKeyNumber, Session, SessionError, Uid,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::file_settings::CryptoMode,
};
use std::time::Duration;

use crate::transport::PcscTransport;

/// Factory default key (all zeros).
const FACTORY_KEY: [u8; 16] = [0u8; 16];
const FACTORY_KEY_VERSION: u8 = 0x00;

/// Boltcard SDM options: K1 = PICC encryption, K2 = CMAC generation.
///
/// Per boltcard protocol: the worker decrypts `p=` with K1 (`decryptP(pHex, k1Keys)`)
/// and verifies `c=` with K2 (`verifyCmac(uidBytes, ctr, cHex, k2Bytes)`).
/// The `[[` template marker in the URL creates an empty MAC input window,
/// which matches what `@ntag424/crypto` `verifyCmac()` expects (no file data in MAC).
fn boltcard_sdm_opts() -> SdmUrlOptions {
    SdmUrlOptions {
        picc_key: KeyNumber::Key1,
        mac_key: KeyNumber::Key2,
        ..SdmUrlOptions::new()
    }
}

/// Extract a fixed 7-byte UID from the ntag424 Uid enum.
fn uid_to_fixed(uid: &Uid) -> [u8; 7] {
    match uid {
        Uid::Fixed(f) => *f,
        Uid::Random(_) => [0u8; 7],
    }
}

/// Check if a session error is an authentication delay.
fn is_auth_delay<T: std::error::Error + std::fmt::Debug>(err: &SessionError<T>) -> bool {
    matches!(
        err,
        SessionError::ErrorResponse(ntag424::types::ResponseStatus::AuthenticationDelay)
    )
}

/// Generate random 16-byte nonce.
fn gen_rnd_a() -> anyhow::Result<[u8; 16]> {
    let mut rnd_a = [0u8; 16];
    getrandom::fill(&mut rnd_a).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    Ok(rnd_a)
}

/// Read and print card UID.
pub async fn cmd_uid(transport: &mut PcscTransport) -> anyhow::Result<[u8; 7]> {
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("UID: {}", hex::encode(uid_fixed));
    Ok(uid_fixed)
}

/// Inspect card: UID, version, file settings, NDEF content (all unauthenticated).
pub async fn cmd_inspect(transport: &mut PcscTransport) -> anyhow::Result<()> {
    let mut session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    println!("UID: {}", hex::encode(uid.as_ref()));

    match session.get_version(transport).await {
        Ok(v) => {
            println!(
                "Version: HW vendor={:02X} type={:02X} ver={:02X}.{:02X} | SW vendor={:02X} type={:02X} ver={:02X}.{:02X} | Batch={} CW{} {}",
                v.hw_vendor_id(),
                v.hw_type(),
                v.hw_major_version(),
                v.hw_minor_version(),
                v.sw_vendor_id(),
                v.sw_type(),
                v.sw_major_version(),
                v.sw_minor_version(),
                v.batch_number(),
                v.calendar_week_of_production(),
                v.calendar_year_of_production(),
            );
        }
        Err(e) => println!("Version: (unreadable: {e})"),
    }

    match session.get_file_settings(transport, File::Ndef).await {
        Ok(settings) => {
            println!("NDEF file settings: {settings:?}");
        }
        Err(e) => println!("NDEF file settings: (unreadable: {e})"),
    }

    let mut buf = [0u8; 256];
    match session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
    {
        Ok(len) => {
            println!("NDEF content ({} bytes): {}", len, hex::encode(&buf[..len]));
            // Try to display as UTF-8 for URLs
            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                println!("NDEF (text): {s}");
            }
        }
        Err(e) => println!("NDEF content: (unreadable: {e})"),
    }

    Ok(())
}

/// Burn a card: write SDM NDEF, enable SDM, install derived keys.
pub async fn cmd_burn(
    transport: &mut PcscTransport,
    issuer_key: &[u8; 16],
    url: &str,
    version: u8,
) -> anyhow::Result<()> {
    // Step 1: Build SDM NDEF config from URL
    let plan = sdm_url_config(url, CryptoMode::Aes, boltcard_sdm_opts())
        .map_err(|e| anyhow::anyhow!("SDM URL config error: {e}"))?;

    // Step 2: Read UID
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID: {}", hex::encode(uid_fixed));

    // Step 3: Derive keys
    let keys = BoltcardDeterministicDeriver::derive_keys(issuer_key, &uid_fixed, version as u32);
    print_derived_keys(&keys, version);

    // Step 4: Authenticate with factory K0 first — card may require auth for writes
    println!("Authenticating with factory key...");
    let rnd_a = gen_rnd_a()?;

    let mut session = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        Ok(s) => s,
        Err(e) if is_auth_delay(&e) => {
            println!("Authentication delay, waiting 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let rnd_a = gen_rnd_a()?;
            Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
                .await?
        }
        Err(e) => return Err(e).context("authentication failed"),
    };

    // Step 5: Write NDEF using authenticated session
    println!("Writing NDEF template...");
    session
        .write_file_plain(transport, File::Ndef, 0, &plan.ndef_bytes)
        .await
        .context("failed to write NDEF")?;

    // Step 6: Enable SDM in file settings
    println!("Configuring SDM file settings...");
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read file settings")?;
    let update = settings.into_update().with_sdm(plan.sdm_settings);
    let session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await
        .context("failed to change file settings")?;

    // Step 7-10: Change K1-K4 (non-master keys first, old key = factory)
    println!("Installing K1...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key1,
            &keys.k1,
            version,
            &FACTORY_KEY,
        )
        .await
        .context("failed to change K1")?;

    println!("Installing K2...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key2,
            &keys.k2,
            version,
            &FACTORY_KEY,
        )
        .await
        .context("failed to change K2")?;

    println!("Installing K3...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key3,
            &keys.k3,
            version,
            &FACTORY_KEY,
        )
        .await
        .context("failed to change K3")?;

    println!("Installing K4...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key4,
            &keys.k4,
            version,
            &FACTORY_KEY,
        )
        .await
        .context("failed to change K4")?;

    // Step 11: Change master key (K0) last — invalidates session
    println!("Installing K0 (master key)...");
    session
        .change_master_key(transport, &keys.k0, version)
        .await
        .context("failed to change master key")?;

    println!("Card burned successfully!");
    Ok(())
}

/// Wipe a card: authenticate with derived K0, clear SDM, reset all keys to factory.
pub async fn cmd_wipe(
    transport: &mut PcscTransport,
    issuer_key: &[u8; 16],
    version: u8,
) -> anyhow::Result<()> {
    // Step 1: Read UID
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID: {}", hex::encode(uid_fixed));

    // Step 2: Derive current keys
    let keys = BoltcardDeterministicDeriver::derive_keys(issuer_key, &uid_fixed, version as u32);
    println!("Derived K0: {}", hex::encode(keys.k0));

    // Step 3: Authenticate with derived K0
    println!("Authenticating with derived K0...");
    let rnd_a = gen_rnd_a()?;

    let session = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
        .await
    {
        Ok(s) => s,
        Err(e) if is_auth_delay(&e) => {
            println!("Authentication delay, waiting 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let rnd_a = gen_rnd_a()?;
            Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, &keys.k0, rnd_a)
                .await?
        }
        Err(e) => return Err(e).context("authentication failed"),
    };

    // Step 4: Clear SDM from file settings
    println!("Clearing SDM settings...");
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read file settings")?;
    let update = settings.into_update(); // No SDM = cleared
    let mut session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await
        .context("failed to clear file settings")?;

    // NDEF Type 4 Tag spec: first 2 bytes = NLEN (big-endian length of NDEF message).
    // NLEN=0 means empty NDEF — no records. Was [0u8; 8] which worked in practice
    // but 2 bytes is the spec-correct minimum (NFC Forum NDEF Type 4 Tag §4.1).
    let empty_ndef = [0x00u8, 0x00];
    session
        .write_file_plain(transport, File::Ndef, 0, &empty_ndef)
        .await
        .context("failed to write empty NDEF")?;

    // Step 6: Reset K1-K4 to factory (old keys = derived keys)
    println!("Resetting K1...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key1,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys.k1,
        )
        .await
        .context("failed to reset K1")?;

    println!("Resetting K2...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key2,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys.k2,
        )
        .await
        .context("failed to reset K2")?;

    println!("Resetting K3...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key3,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys.k3,
        )
        .await
        .context("failed to reset K3")?;

    println!("Resetting K4...");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key4,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys.k4,
        )
        .await
        .context("failed to reset K4")?;

    // Step 7: Reset K0 last
    println!("Resetting K0 (master key)...");
    session
        .change_master_key(transport, &FACTORY_KEY, FACTORY_KEY_VERSION)
        .await
        .context("failed to reset master key")?;

    println!("Card wiped successfully!");
    Ok(())
}

fn print_derived_keys(keys: &CardKeySet, version: u8) {
    println!("Derived keys (version {version}):");
    println!("  cardKey: {}", hex::encode(keys.card_key));
    println!("  K0:      {}", hex::encode(keys.k0));
    println!("  K1:      {}", hex::encode(keys.k1));
    println!("  K2:      {}", hex::encode(keys.k2));
    println!("  K3:      {}", hex::encode(keys.k3));
    println!("  K4:      {}", hex::encode(keys.k4));
}
