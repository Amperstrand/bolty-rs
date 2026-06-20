use std::time::Duration;

use anyhow::Context;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use bolty_ntag::{KeyNumber, Session, Transport};

use crate::audit;
use crate::common::{gen_rnd_a, record_auth_failure};

pub async fn cmd_scan_keys<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    json_mode: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_hex = crate::to_hex(uid);

    if !json_mode {
        println!("Card UID: {uid_hex}\n");
    }

    let uid_fixed = crate::common::uid_to_fixed(&uid);
    let card_uid = CardUid::new(uid_fixed);

    let factory = [0u8; 16];
    let static_test = [0x11u8; 16];

    let v0 = BoltcardDeterministicDeriver::derive_keys(issuer_key, card_uid, 0);
    let v1 = BoltcardDeterministicDeriver::derive_keys(issuer_key, card_uid, 1);
    let v2 = BoltcardDeterministicDeriver::derive_keys(issuer_key, card_uid, 2);
    let v3 = BoltcardDeterministicDeriver::derive_keys(issuer_key, card_uid, 3);

    let candidates: [(&str, [u8; 16]); 7] = [
        ("factory K0 (zeros)", factory),
        ("derived K0 v0", *v0.k0.as_bytes()),
        ("derived K0 v1", *v1.k0.as_bytes()),
        ("derived K0 v2", *v2.k0.as_bytes()),
        ("derived K0 v3", *v3.k0.as_bytes()),
        ("static test key (0x11..11)", static_test),
        ("card key v1", *v1.card_key.as_bytes()),
    ];

    if !json_mode {
        println!("Scanning {} key candidates...\n", candidates.len());
    }

    for (i, (label, key)) in candidates.iter().enumerate() {
        if !json_mode {
            println!("[{}/{}] Trying {}...", i + 1, candidates.len(), label);
        }
        audit::log_event(&format!("scan-keys: trying {label}"));

        match try_auth(transport, key).await {
            AuthResult::Success => {
                let key_hex = crate::to_hex(key);
                audit::log_event(&format!("scan-keys: ACCEPTED {label} = {key_hex}"));
                if json_mode {
                    println!(
                        r#"{{"ok":true,"uid":"{uid_hex}","found":true,"label":"{label}","key":"{key_hex}"}}"#
                    );
                } else {
                    println!("  ✅ KEY ACCEPTED: {label}");
                    println!("  Key: {key_hex}");
                    println!("\n🎉 Found the key! Recovery path:");
                    println!("  1. This key is the current K0 on the card.");
                    println!(
                        "  2. Wipe: bolty-cli wipe --issuer-key <your-issuer-key> --version <N>"
                    );
                    println!("  3. Or use try-key to confirm, then wipe from M5StickC.");
                }
                return Ok(());
            }
            AuthResult::WrongKey => {
                record_auth_failure();
                if !json_mode {
                    println!("  ❌ rejected");
                }
                audit::log_event(&format!("scan-keys: REJECTED {label}"));
            }
            AuthResult::AuthDelay => {
                audit::log_event("scan-keys: AUTH DELAY detected, aborting");
                if json_mode {
                    println!(
                        r#"{{"ok":false,"uid":"{uid_hex}","error":"auth_delay_during_scan"}}"#
                    );
                } else {
                    println!("  ⚠️  auth delay (91AD) — stopping scan");
                    println!("  Use try-key to clear delay (rapid retry within same connection).");
                }
                anyhow::bail!("auth delay triggered during scan");
            }
            AuthResult::Error(e) => {
                if !json_mode {
                    println!("  ⚠️  error: {e}");
                }
                audit::log_event(&format!("scan-keys: ERROR on {label}: {e}"));
            }
        }

        if i + 1 < candidates.len() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    audit::log_event("scan-keys: no candidate matched");
    if json_mode {
        println!(r#"{{"ok":true,"uid":"{uid_hex}","found":false}}"#);
    } else {
        println!("\n❌ No candidate key worked.");
        println!("The card may have been burned by a different tool with unknown keys,");
        println!("or TotFailCtr may have reached 1000 (permanent lock).");
    }

    Ok(())
}

enum AuthResult {
    Success,
    WrongKey,
    AuthDelay,
    Error(String),
}

async fn try_auth<T: Transport>(transport: &mut T, key: &[u8; 16]) -> AuthResult
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let rnd_a = match gen_rnd_a() {
        Ok(r) => r,
        Err(e) => return AuthResult::Error(format!("RNG: {e}")),
    };

    match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, key, rnd_a)
        .await
    {
        Ok(_) => AuthResult::Success,
        Err(bolty_ntag::SessionError::ErrorResponse(
            bolty_ntag::ResponseStatus::AuthenticationError,
        )) => AuthResult::WrongKey,
        Err(bolty_ntag::SessionError::ErrorResponse(
            bolty_ntag::ResponseStatus::AuthenticationDelay,
        )) => AuthResult::AuthDelay,
        Err(e) => AuthResult::Error(format!("{e:?}")),
    }
}
