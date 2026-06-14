use anyhow::Context;
use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::{BoltcardDeterministicDeriver, CardKeySet};
use bolty_core::uid::CardUid;
use ntag424::{
    AuthenticatedSession, File, KeyNumber, NonMasterKeyNumber, Session, Transport,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::file_settings::{CryptoMode, Sdm},
};
use std::time::Duration;

use crate::common::{gen_rnd_a, is_auth_delay, uid_to_fixed};

fn boltcard_sdm_opts() -> SdmUrlOptions {
    SdmUrlOptions {
        picc_key: KeyNumber::Key1,
        mac_key: KeyNumber::Key2,
        ..SdmUrlOptions::new()
    }
}

pub async fn cmd_burn<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    url: &str,
    version: u8,
    verbose: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let plan = sdm_url_config(url, CryptoMode::Aes, boltcard_sdm_opts())
        .map_err(|e| anyhow::anyhow!("SDM URL config error: {e}"))?;

    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID: {}", crate::to_hex(uid_fixed));

    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        version as u32,
    );
    if verbose {
        print_derived_keys(&keys, version);
    }

    // --- Authenticate: factory K0 for fresh cards, derived K0 for re-burns ---
    println!("[1/7] Authenticating...");
    let rnd_a = gen_rnd_a()?;
    let (session, old_keys_are_factory) = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        Ok(s) => {
            println!("  Authenticated with factory K0");
            (s, true)
        }
        Err(_) => {
            // Factory K0 failed — card may have derived keys from a previous burn
            println!("  Factory K0 failed, trying derived K0...");
            let rnd_a = gen_rnd_a()?;
            match Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, keys.k0.as_bytes(), rnd_a)
                .await
            {
                Ok(s) => {
                    println!("  Authenticated with derived K0 (re-burn)");
                    (s, false)
                }
                Err(e) => {
                    if is_auth_delay(&e) {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    return Err(e).context(
                        "authentication failed with both factory and derived K0 — \
                         card may use a different issuer key",
                    );
                }
            }
        }
    };

    // Clear any residual SDM from a previous burn before writing NDEF.
    // SDM must be off when we write NDEF, otherwise the SDM engine processes
    // the placeholder bytes on readback and the verification comparison fails.
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read file settings")?;
    let mut session = session;
    if settings.sdm.is_some() {
        println!("  Clearing residual SDM from previous burn...");
        let update = settings.into_update().with_sdm(Sdm::disabled());
        session = session
            .change_file_settings(transport, File::Ndef, &update)
            .await
            .context("failed to clear residual SDM")?;
    }

    // --- Write NDEF + verify prefix ---
    println!(
        "[2/7] Writing NDEF template ({} bytes)...",
        plan.ndef_bytes.len()
    );
    session
        .write_file_plain(transport, File::Ndef, 0, &plan.ndef_bytes)
        .await
        .context("failed to write NDEF")?;

    let mut read_buf = [0u8; 256];
    let read_len = session
        .read_file_plain(transport, File::Ndef, 0, 0, &mut read_buf)
        .await
        .context("failed to read back NDEF for verification")?;

    // NDEF file is typically 256 bytes; only compare the bytes we actually wrote
    // SAFETY: read_buf is [u8; 256], NDEF templates are always <= 256 bytes.
    #[allow(clippy::indexing_slicing)]
    if read_len < plan.ndef_bytes.len() || read_buf[..plan.ndef_bytes.len()] != plan.ndef_bytes[..]
    {
        anyhow::bail!(
            "NDEF verification failed: wrote {} bytes, read back {} bytes — prefix mismatch.\n\
             Card state: NDEF may be corrupt, K0=factory → re-burn should fix this.",
            plan.ndef_bytes.len(),
            read_len
        );
    }
    println!(
        "  ✓ NDEF verified ({} bytes written)",
        plan.ndef_bytes.len()
    );

    // --- Configure SDM + verify ---
    println!("[3/7] Configuring SDM file settings...");
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read back file settings for verification")?;
    let session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &settings.into_update().with_sdm(plan.sdm_settings),
        )
        .await
        .context("failed to configure SDM")?;

    let (verify_settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to verify SDM file settings")?;
    if verify_settings.sdm.is_none() {
        anyhow::bail!(
            "SDM verification failed: file settings show no SDM configured.\n\
             Card state: NDEF correct, SDM not active, K0=factory → re-burn should fix this."
        );
    }
    println!("  ✓ SDM configured and verified");

    // --- Install K1-K4 ---
    let key_steps: [(NonMasterKeyNumber, &[u8; 16], &str); 4] = [
        (NonMasterKeyNumber::Key1, keys.k1.as_bytes(), "K1"),
        (NonMasterKeyNumber::Key2, keys.k2.as_bytes(), "K2"),
        (NonMasterKeyNumber::Key3, keys.k3.as_bytes(), "K3"),
        (NonMasterKeyNumber::Key4, keys.k4.as_bytes(), "K4"),
    ];
    let derived_keys = [
        keys.k1.as_bytes(),
        keys.k2.as_bytes(),
        keys.k3.as_bytes(),
        keys.k4.as_bytes(),
    ];

    let mut session = session;
    // SAFETY: i from enumerate over key_steps (4 items); derived_keys has 4 items.
    #[allow(clippy::indexing_slicing)]
    for (i, (key_no, new_key, label)) in key_steps.iter().enumerate() {
        let step = 4 + i;
        let old_key: &[u8; 16] = if old_keys_are_factory {
            &FACTORY_KEY
        } else {
            derived_keys[i]
        };
        println!("[{step}/7] Installing {label}...");
        match session
            .change_key(transport, *key_no, new_key, version, old_key)
            .await
        {
            Ok(s) => {
                println!("  ✓ {label} installed");
                session = s;
            }
            Err(e) => {
                let already_changed: Vec<&str> =
                    key_steps[..i].iter().map(|(_, _, l)| *l).collect();
                anyhow::bail!(
                    "Failed to install {label}: {e:#}\n\
                     Card state: NDEF ✓, SDM ✓, K0=factory, changed keys: [{}]\n\
                     Recovery: re-run burn (factory K0 still active, changed keys will be overwritten)",
                    already_changed.join(", ")
                );
            }
        }
    }

    // --- Install K0 (master) ---
    println!("[7/7] Installing K0 (master key)...");
    session
        .change_master_key(transport, keys.k0.as_bytes(), version)
        .await
        .context(
            "Failed to install K0 (master key).\n\
             Card state: NDEF ✓, SDM ✓, K1-K4 changed, K0=factory.\n\
             Recovery: re-run burn immediately (factory K0 still active).",
        )?;
    println!("  ✓ K0 installed");

    // --- Post-burn verification ---
    println!("\nVerifying burn...");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let rnd_a = gen_rnd_a()?;
    let verify_session = match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, keys.k0.as_bytes(), rnd_a)
        .await
    {
        Ok(s) => s,
        Err(e) if is_auth_delay(&e) => {
            println!("  Authentication delay, waiting 1s...");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let rnd_a = gen_rnd_a()?;
            Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, keys.k0.as_bytes(), rnd_a)
                .await
                .context(
                    "POST-BURN VERIFICATION FAILED: Cannot authenticate with new K0.\n\
                     Try: bolty-cli wipe and re-burn.",
                )?
        }
        Err(e) => {
            return Err(e).context(
                "POST-BURN VERIFICATION FAILED: Cannot authenticate with new K0.\n\
                 Try: bolty-cli wipe and re-burn.",
            );
        }
    };

    let (final_settings, _) = verify_session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("POST-BURN VERIFICATION FAILED: Cannot read file settings with new K0")?;

    if final_settings.sdm.is_none() {
        anyhow::bail!(
            "POST-BURN VERIFICATION FAILED: SDM not active after burn.\n\
             Card is authenticated with new K0 but SDM is missing."
        );
    }

    println!("  ✓ K0 authentication verified");
    println!("  ✓ SDM active");
    println!("\n✅ Card burned and verified successfully!");
    Ok(())
}

fn print_derived_keys(keys: &CardKeySet, version: u8) {
    println!("Derived keys (version {version}):");
    println!("  cardKey: {}", crate::to_hex(keys.card_key.as_bytes()));
    println!("  K0:      {}", crate::to_hex(keys.k0.as_bytes()));
    println!("  K1:      {}", crate::to_hex(keys.k1.as_bytes()));
    println!("  K2:      {}", crate::to_hex(keys.k2.as_bytes()));
    println!("  K3:      {}", crate::to_hex(keys.k3.as_bytes()));
    println!("  K4:      {}", crate::to_hex(keys.k4.as_bytes()));
}
