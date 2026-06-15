use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::{BoltcardDeterministicDeriver, CardKeySet};
use bolty_core::uid::CardUid;
use ntag424::{
    KeyNumber, Session, Transport,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::file_settings::CryptoMode,
};

use crate::common::{AuthRetry, gen_rnd_a, is_auth_delay, map_ntag_error};

pub async fn cmd_burn<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    url: &str,
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
                "UID mismatch: expected {}, got {} — refusing to burn wrong card",
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
        print_derived_keys(&keys, version);
    }

    if dry_run {
        let sdm_opts = SdmUrlOptions {
            picc_key: KeyNumber::Key1,
            mac_key: KeyNumber::Key2,
            ..SdmUrlOptions::new()
        };
        let ndef_size = sdm_url_config(url, CryptoMode::Aes, sdm_opts)
            .map_err(|e| anyhow::anyhow!("SDM URL config error: {e}"))?
            .ndef_bytes
            .len();

        println!("\n=== DRY RUN — no card modifications ===");
        println!("URL:       {url}");
        println!("Version:   {version}");
        println!("NDEF size: {ndef_size} bytes");
        println!("\nPlanned steps:");
        println!("  [1] Authenticate (factory K0 or derived K0)");
        println!("  [2] Write NDEF template + verify readback");
        println!("  [3] Configure SDM file settings + verify");
        println!("  [4] Install K1");
        println!("  [5] Install K2");
        println!("  [6] Install K3");
        println!("  [7] Install K4, then K0 (master)");
        println!("  Post:  Re-authenticate with new K0 + verify SDM");
        println!("\nNo APDUs sent. Card unchanged.");
        return Ok(());
    }

    // --- Probe auth: determine current_key and previous_keys ---
    // Try factory K0 first (fresh card), then derived K0 (re-burn).
    // This probe is separate from the library's internal auth — the card supports re-auth.
    println!("[1/7] Authenticating...");
    let (current_key, previous_keys): ([u8; 16], bolty_ntag::KeySet) = {
        let factory_works = {
            let mut retry = AuthRetry::new();
            loop {
                let rnd_a = gen_rnd_a()?;
                match Session::default()
                    .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
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
            }
        };

        if factory_works {
            println!("  Authenticated with factory K0");
            (FACTORY_KEY, [FACTORY_KEY; 5])
        } else {
            println!("  Factory K0 rejected, trying derived K0...");
            let mut retry = AuthRetry::new();
            let derived_works = loop {
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

            if derived_works {
                println!("  Authenticated with derived K0 (re-burn)");
                let derived_keyset: bolty_ntag::KeySet = [
                    *keys.k0.as_bytes(),
                    *keys.k1.as_bytes(),
                    *keys.k2.as_bytes(),
                    *keys.k3.as_bytes(),
                    *keys.k4.as_bytes(),
                ];
                (*keys.k0.as_bytes(), derived_keyset)
            } else {
                anyhow::bail!(
                    "authentication failed with both factory and derived K0 — \
                     card may use a different issuer key"
                );
            }
        }
    };

    // --- Delegate to library: it handles NDEF write, SDM config, key install, verification ---
    let new_keys: bolty_ntag::KeySet = [
        *keys.k0.as_bytes(),
        *keys.k1.as_bytes(),
        *keys.k2.as_bytes(),
        *keys.k3.as_bytes(),
        *keys.k4.as_bytes(),
    ];

    let params = bolty_ntag::BurnParams {
        lnurl: url,
        keys: new_keys,
        key_version: version,
        current_key,
        previous_keys,
    };

    let rnd_a = gen_rnd_a()?;
    println!("\nBurning card...");
    if let Err(e) = bolty_ntag::burn(transport, &params, rnd_a).await {
        return Err(map_ntag_error(e));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_preserves_factory_card_state() {
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";

        let keys_before = *transport.keys();
        let ndef_before = transport.ndef().to_vec();
        let settings_before = transport.file_settings().to_vec();

        let result = cmd_burn(&mut transport, &issuer_key, url, 1, false, true, None).await;
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

    #[tokio::test]
    async fn confirm_uid_rejects_mismatch() {
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        let wrong_uid = [0xFFu8; 7];

        let keys_before = transport.keys().clone();

        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            Some(&wrong_uid),
        )
        .await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("UID mismatch"),
            "error should mention UID mismatch: {msg}"
        );

        assert_eq!(
            transport.keys(),
            &keys_before,
            "no keys should change on UID mismatch"
        );
    }

    #[tokio::test]
    async fn confirm_uid_accepts_match() {
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        let correct_uid = crate::mock_transport::UID;

        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            true,
            Some(&correct_uid),
        )
        .await;

        assert!(
            result.is_ok(),
            "dry-run with correct UID should pass: {:?}",
            result.err()
        );
    }
}
