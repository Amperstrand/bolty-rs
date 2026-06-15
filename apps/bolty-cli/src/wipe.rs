use anyhow::Context;
use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use bolty_ntag::{AuthenticatedSession, File, KeyNumber, Session, Transport};

use crate::common::{
    AuthRetry, gen_rnd_a, is_auth_delay, is_sdm_functionally_active, map_ntag_error,
};

pub async fn cmd_wipe<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    version: u8,
    verbose: bool,
    dry_run: bool,
    confirm_uid: Option<&[u8; 7]>,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid_fixed = bolty_ntag::preflight(transport)
        .await
        .map_err(map_ntag_error)?;
    println!("Card UID: {}", crate::to_hex(uid_fixed));

    if let Some(expected) = confirm_uid {
        if uid_fixed != *expected {
            anyhow::bail!(
                "UID mismatch: expected {}, got {} — refusing to wipe wrong card",
                crate::to_hex(expected),
                crate::to_hex(uid_fixed),
            );
        }
        println!("  ✓ UID confirmed");
    }

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

    // Factory K0 probe: detect already-wiped cards (single attempt, no retry).
    // If factory K0 works and the card is clean, return early.
    // If factory K0 works but card has residual state, bail with instructions.
    let rnd_a = gen_rnd_a()?;
    if let Ok(session) = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        let (settings, mut session) = session
            .get_file_settings(transport, File::Ndef)
            .await
            .context("failed to read file settings with factory K0")?;

        let has_sdm = is_sdm_functionally_active(settings.sdm.as_ref());
        let mut buf = [0u8; 256];
        let len = session
            .read_file_plain(transport, File::Ndef, 0, 0, &mut buf)
            .await
            .context("failed to read NDEF with factory K0")?;
        #[allow(clippy::indexing_slicing)]
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

    // Derived K0 auth with AuthRetry (handles auth delay backoff).
    // The library re-authenticates internally, but we probe first to get
    // past any auth delay and give a clear error message on failure.
    println!("Authenticating with derived K0...");
    {
        let mut retry = AuthRetry::new();
        let result = loop {
            let rnd_a = gen_rnd_a()?;
            match Session::default()
                .authenticate_aes(transport, KeyNumber::Key0, keys.k0.as_bytes(), rnd_a)
                .await
            {
                Ok(_) => break true,
                Err(e) if is_auth_delay(&e) => match retry.next_delay() {
                    Some(d) => {
                        tokio::time::sleep(d).await;
                    }
                    None => anyhow::bail!("{}", AuthRetry::exhausted_msg()),
                },
                Err(_) => break false,
            }
        };
        if !result {
            anyhow::bail!("derived K0 authentication failed — wrong issuer key or card not burned");
        }
    }

    // Delegate to library: it handles SDM disable, NDEF clear, key reset, verification.
    let keyset: bolty_ntag::KeySet = [
        *keys.k0.as_bytes(),
        *keys.k1.as_bytes(),
        *keys.k2.as_bytes(),
        *keys.k3.as_bytes(),
        *keys.k4.as_bytes(),
    ];

    let rnd_a = gen_rnd_a()?;
    println!("\nWiping card...");
    if let Err(e) = bolty_ntag::wipe(transport, &keyset, rnd_a).await {
        return Err(map_ntag_error(e));
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

        crate::burn::cmd_burn(&mut transport, &issuer_key, url, 1, false, false, None)
            .await
            .expect("burn to provision card for wipe dry-run test");

        let keys_before = *transport.keys();
        let ndef_before = transport.ndef().to_vec();
        let settings_before = transport.file_settings().to_vec();

        let result = cmd_wipe(&mut transport, &issuer_key, 1, false, true, None).await;
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
