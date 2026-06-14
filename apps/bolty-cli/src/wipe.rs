use anyhow::Context;
use bolty_core::constants::{FACTORY_KEY, KEY_VERSION_BLANK};
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use ntag424::{
    AuthenticatedSession, File, KeyNumber, NonMasterKeyNumber, Session, Transport,
    types::file_settings::{PiccData, Sdm},
};
use std::time::Duration;

use crate::common::{gen_rnd_a, is_auth_delay, preflight_check};

pub async fn cmd_wipe<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    version: u8,
    verbose: bool,
    dry_run: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid_fixed = preflight_check(transport).await?;
    println!("Card UID: {}", crate::to_hex(uid_fixed));

    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        version as u32,
    );
    if verbose || dry_run {
        println!("Derived K0: {}", crate::to_hex(keys.k0.as_bytes()));
    }

    if dry_run {
        println!("\n=== DRY RUN — no card modifications ===");
        println!("Version:   {version}");
        println!("\nPlanned steps:");
        println!("  [1] Authenticate (factory K0 or derived K0)");
        println!("  [2] Clear SDM file settings");
        println!("  [3] Write empty NDEF (NLEN=0)");
        println!("  [4] Reset K1 to factory");
        println!("  [5] Reset K2 to factory");
        println!("  [6] Reset K3 to factory");
        println!("  [7] Reset K4 to factory, then K0 (master)");
        println!("  Post:  Re-authenticate with factory K0 + verify");
        println!("\nNo APDUs sent. Card unchanged.");
        return Ok(());
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

    // Reset K1-K4 to factory with per-key verification
    #[allow(clippy::type_complexity)]
    let key_steps: [(NonMasterKeyNumber, KeyNumber, &[u8; 16], &[u8; 16], &str); 4] = [
        (
            NonMasterKeyNumber::Key1,
            KeyNumber::Key1,
            &FACTORY_KEY,
            keys.k1.as_bytes(),
            "K1",
        ),
        (
            NonMasterKeyNumber::Key2,
            KeyNumber::Key2,
            &FACTORY_KEY,
            keys.k2.as_bytes(),
            "K2",
        ),
        (
            NonMasterKeyNumber::Key3,
            KeyNumber::Key3,
            &FACTORY_KEY,
            keys.k3.as_bytes(),
            "K3",
        ),
        (
            NonMasterKeyNumber::Key4,
            KeyNumber::Key4,
            &FACTORY_KEY,
            keys.k4.as_bytes(),
            "K4",
        ),
    ];

    let mut session = session;
    // SAFETY: i from enumerate, key_steps[..i] always valid.
    #[allow(clippy::indexing_slicing)]
    for (i, (key_no, kn, new_key, old_key, label)) in key_steps.iter().enumerate() {
        println!("Resetting {label}...");
        match session
            .change_key(transport, *key_no, new_key, KEY_VERSION_BLANK, old_key)
            .await
        {
            Ok(s) => {
                let (v, s2) = s
                    .get_key_version(transport, *kn)
                    .await
                    .with_context(|| format!("failed to read back {label} version"))?;
                if v != KEY_VERSION_BLANK {
                    anyhow::bail!(
                        "{label} version mismatch: expected {KEY_VERSION_BLANK:#04X}, got {v:#04X}.\n\
                         Card state: partially wiped (reset: [{}])\n\
                         Recovery: re-run burn, then wipe again",
                        key_steps[..i]
                            .iter()
                            .map(|(_, _, _, _, l)| *l)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                println!("  ✓ {label} reset to factory (v{v:#04X})");
                session = s2;
            }
            Err(e) => {
                let already_reset: Vec<&str> =
                    key_steps[..i].iter().map(|(_, _, _, _, l)| *l).collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_preserves_provisioned_card_state() {
        let mut transport = crate::mock_transport::MockTransport::new();

        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";

        crate::burn::cmd_burn(&mut transport, &issuer_key, url, 1, false, false)
            .await
            .expect("burn to provision card for wipe dry-run test");

        let keys_before = transport.keys().clone();
        let ndef_before = transport.ndef().to_vec();
        let settings_before = transport.file_settings().to_vec();

        let result = cmd_wipe(&mut transport, &issuer_key, 1, false, true).await;
        assert!(result.is_ok(), "dry-run should succeed: {:?}", result.err());

        assert_eq!(
            transport.keys(),
            &keys_before,
            "keys must not change during dry-run"
        );
        assert_eq!(
            transport.ndef(),
            &ndef_before[..],
            "NDEF must not change during dry-run"
        );
        assert_eq!(
            transport.file_settings(),
            &settings_before[..],
            "file settings must not change during dry-run"
        );
    }
}
