use anyhow::Context;
use bolty_core::provenance::KeyProvenance;
use bolty_ntag::{KeyNumber, Session, Transport};

use crate::audit;
use crate::common::gen_rnd_a;

pub async fn cmd_try_key<T: Transport>(
    transport: &mut T,
    key: &[u8; 16],
    key_no: u8,
    attempts: u32,
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
    let key_hex = crate::to_hex(key);

    if !json_mode {
        println!("Card UID: {uid_hex}");
    }

    let target_key = match key_no {
        0 => KeyNumber::Key0,
        1 => KeyNumber::Key1,
        2 => KeyNumber::Key2,
        3 => KeyNumber::Key3,
        4 => KeyNumber::Key4,
        n => anyhow::bail!("invalid key number {n} (must be 0-4)"),
    };

    if !json_mode {
        println!("\nTrying K{key_no} = {key_hex} ...");
    }
    audit::log_event_with_provenance(
        &format!("try-key: K{key_no} = {key_hex}"),
        Some(KeyProvenance::UnknownExternal),
    );

    let attempts = attempts.clamp(1, 1000);
    for attempt in 1..=attempts {
        let rnd_a = gen_rnd_a()?;
        match Session::default()
            .authenticate_aes(transport, target_key, key, rnd_a)
            .await
        {
            Ok(_) => {
                audit::log_event_with_provenance(
                    &format!("try-key: ACCEPTED K{key_no}"),
                    Some(KeyProvenance::UnknownExternal),
                );
                if json_mode {
                    println!(
                        r#"{{"ok":true,"uid":"{uid_hex}","accepted":true,"key":"{key_hex}","key_no":{key_no}}}"#
                    );
                } else {
                    println!("✅ Key accepted!");
                    if key_no == 0 {
                        println!("Card can be wiped with this key. Run:");
                        println!("  bolty-cli wipe --issuer-key <derive-from-this-key>");
                    }
                }
                return Ok(());
            }
            Err(bolty_ntag::SessionError::ErrorResponse(
                bolty_ntag::ResponseStatus::AuthenticationError,
            )) => {
                audit::log_event_with_provenance(
                    &format!("try-key: REJECTED K{key_no}"),
                    Some(KeyProvenance::UnknownExternal),
                );
                if json_mode {
                    println!(
                        r#"{{"ok":true,"uid":"{uid_hex}","accepted":false,"reason":"wrong_key","key":"{key_hex}","key_no":{key_no}}}"#
                    );
                } else {
                    println!("❌ Key rejected (wrong key).");
                }
                return Ok(());
            }
            Err(bolty_ntag::SessionError::ErrorResponse(
                bolty_ntag::ResponseStatus::AuthenticationDelay,
            )) => {
                if !json_mode && (attempt <= 3 || attempt % 5 == 0) {
                    println!("  Auth delay (91AD) — keep trying ({attempt}/{attempts})...");
                }
                continue;
            }
            Err(e) => {
                anyhow::bail!("unexpected error: {e:?}");
            }
        }
    }

    audit::log_event_with_provenance(
        &format!("try-key: auth delay persists after {attempts} attempts"),
        Some(KeyProvenance::UnknownExternal),
    );
    if json_mode {
        println!(
            r#"{{"ok":false,"uid":"{uid_hex}","error":"auth_delay_persistent","attempts":{attempts}}}"#
        );
    } else {
        println!("⚠️  Auth delay persists after {attempts} rapid attempts.");
        println!("The card may need a different key or have extensive TotFailCtr.");
    }
    Ok(())
}
