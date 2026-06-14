use anyhow::Context;
use bolty_core::constants::{FACTORY_KEY, KEY_VERSION_BLANK};
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use ntag424::{
    AuthenticatedSession, File, KeyNumber, NonMasterKeyNumber, Session,
    types::file_settings::{PiccData, Sdm},
};
use std::time::Duration;

use crate::common::{gen_rnd_a, is_auth_delay, uid_to_fixed};
use crate::transport::PcscTransport;

pub async fn cmd_wipe(
    transport: &mut PcscTransport,
    issuer_key: &[u8; 16],
    version: u8,
    verbose: bool,
) -> anyhow::Result<()> {
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
        println!("Derived K0: {}", crate::to_hex(keys.k0.as_bytes()));
    }

    // Probe card state: try factory K0 first, then derived K0
    let rnd_a = gen_rnd_a()?;
    // Factory K0 failure means card has derived keys — fall through to derived-K0 auth below.
    if let Ok(session) = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        let (settings, mut session) = session
            .get_file_settings(transport, File::Ndef)
            .await
            .context("failed to read file settings with factory K0")?;

        let has_sdm = settings.sdm.is_some();
        let mut buf = [0u8; 256];
        let len = session
            .read_file_plain(transport, File::Ndef, 0, 0, &mut buf)
            .await
            .context("failed to read NDEF with factory K0")?;
        let has_ndef = len >= 2 && (buf[0] != 0x00 || buf[1] != 0x00);

        if !has_sdm && !has_ndef {
            println!("Card already wiped (factory keys, no SDM, empty NDEF). Nothing to do.");
            return Ok(());
        }
        anyhow::bail!(
            "Factory K0 works but card has residual state (SDM={}, NDEF={} bytes).\n\
             Card may have been partially wiped. Use `burn` to re-burn first, then `wipe`.",
            has_sdm,
            if has_ndef { len } else { 0 }
        );
    }

    println!("Authenticating with derived K0...");
    let rnd_a = gen_rnd_a()?;
    let session = match Session::default()
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
                .context("derived K0 authentication failed — wrong issuer key or card not burned")?
        }
        Err(e) => {
            return Err(e)
                .context("derived K0 authentication failed — wrong issuer key or card not burned");
        }
    };

    // Clear SDM by explicitly setting disabled SDM (not just into_update which preserves it)
    println!("Clearing SDM settings...");
    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .context("failed to read file settings")?;
    let update = settings.into_update().with_sdm(Sdm::disabled());
    let mut session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await
        .context("failed to clear file settings")?;

    let empty_ndef = [0x00u8, 0x00];
    session
        .write_file_plain(transport, File::Ndef, 0, &empty_ndef)
        .await
        .context("failed to write empty NDEF")?;

    // Reset K1-K4 to factory
    let key_steps: [(NonMasterKeyNumber, &[u8; 16], &[u8; 16], &str); 4] = [
        (
            NonMasterKeyNumber::Key1,
            &FACTORY_KEY,
            keys.k1.as_bytes(),
            "K1",
        ),
        (
            NonMasterKeyNumber::Key2,
            &FACTORY_KEY,
            keys.k2.as_bytes(),
            "K2",
        ),
        (
            NonMasterKeyNumber::Key3,
            &FACTORY_KEY,
            keys.k3.as_bytes(),
            "K3",
        ),
        (
            NonMasterKeyNumber::Key4,
            &FACTORY_KEY,
            keys.k4.as_bytes(),
            "K4",
        ),
    ];

    let mut session = session;
    // SAFETY: i from enumerate, key_steps[..i] always valid.
    #[allow(clippy::indexing_slicing)]
    for (i, (key_no, new_key, old_key, label)) in key_steps.iter().enumerate() {
        println!("Resetting {label}...");
        match session
            .change_key(transport, *key_no, new_key, KEY_VERSION_BLANK, old_key)
            .await
        {
            Ok(s) => {
                println!("  ✓ {label} reset to factory");
                session = s;
            }
            Err(e) => {
                let already_reset: Vec<&str> =
                    key_steps[..i].iter().map(|(_, _, _, l)| *l).collect();
                anyhow::bail!(
                    "Failed to reset {label}: {e:#}\n\
                     Card state: partially wiped (reset: [{}])\n\
                     Recovery: re-run burn, then wipe again",
                    already_reset.join(", ")
                );
            }
        }
    }

    println!("Resetting K0 (master key)...");
    session
        .change_master_key(transport, &FACTORY_KEY, KEY_VERSION_BLANK)
        .await
        .context("failed to reset master key")?;

    // --- Post-wipe verification ---
    println!("\nVerifying wipe...");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let rnd_a = gen_rnd_a()?;
    match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        Ok(verify) => {
            let (settings, mut verify) = verify
                .get_file_settings(transport, File::Ndef)
                .await
                .context("wipe verification: cannot read file settings")?;
            if let Some(ref sdm) = settings.sdm {
                let has_picc = !matches!(sdm.picc_data(), PiccData::None);
                let has_mac = sdm.file_read().is_some();
                if has_picc || has_mac {
                    anyhow::bail!(
                        "POST-WIPE WARNING: SDM still functionally active (picc={}, mac={})!",
                        has_picc,
                        has_mac
                    );
                }
            }

            let mut buf = [0u8; 256];
            let len = verify
                .read_file_plain(transport, File::Ndef, 0, 0, &mut buf)
                .await
                .context("wipe verification: cannot read NDEF")?;
            // NDEF Type 4 Tag spec: first 2 bytes = NLEN (big-endian). NLEN=0 = empty.
            // The file may contain old data past byte 2; only NLEN matters.
            // SAFETY: buf is [u8; 256], len.min(32) is always <= 32 < 256.
            #[allow(clippy::indexing_slicing)]
            if len < 2 || buf[0] != 0x00 || buf[1] != 0x00 {
                anyhow::bail!(
                    "POST-WIPE WARNING: NDEF not empty ({} bytes: {})",
                    len,
                    crate::to_hex(&buf[..len.min(32)])
                );
            }
            println!("  ✓ Factory K0 works");
            println!("  ✓ SDM cleared");
            println!("  ✓ NDEF empty");
        }
        Err(e) => {
            anyhow::bail!(
                "POST-WIPE VERIFICATION FAILED: Cannot authenticate with factory K0.\n\
                 Card may be in an inconsistent state.\n\
                 Error: {e:#}"
            );
        }
    }

    println!("\n✅ Card wiped and verified successfully!");
    Ok(())
}
