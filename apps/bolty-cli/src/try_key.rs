use anyhow::Context;
use bolty_ntag::{KeyNumber, Session, Transport};

use crate::audit;
use crate::common::gen_rnd_a;

pub async fn cmd_try_key<T: Transport>(
    transport: &mut T,
    key: &[u8; 16],
    key_no: u8,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    println!("Card UID: {}", crate::to_hex(uid));

    let target_key = match key_no {
        0 => KeyNumber::Key0,
        1 => KeyNumber::Key1,
        2 => KeyNumber::Key2,
        3 => KeyNumber::Key3,
        4 => KeyNumber::Key4,
        n => anyhow::bail!("invalid key number {n} (must be 0-4)"),
    };

    println!("\nTrying K{key_no} = {} ...", crate::to_hex(key));
    audit::log_event(&format!("try-key: K{key_no} = {}", crate::to_hex(key)));

    for attempt in 1..=20u32 {
        let rnd_a = gen_rnd_a()?;
        match Session::default()
            .authenticate_aes(transport, target_key, key, rnd_a)
            .await
        {
            Ok(_) => {
                println!("✅ Key accepted!");
                if key_no == 0 {
                    println!("Card can be wiped with this key. Run:");
                    println!("  bolty-cli wipe --issuer-key <derive-from-this-key>");
                }
                return Ok(());
            }
            Err(bolty_ntag::SessionError::ErrorResponse(
                bolty_ntag::ResponseStatus::AuthenticationError,
            )) => {
                println!("❌ Key rejected (wrong key).");
                return Ok(());
            }
            Err(bolty_ntag::SessionError::ErrorResponse(
                bolty_ntag::ResponseStatus::AuthenticationDelay,
            )) => {
                if attempt <= 3 || attempt % 5 == 0 {
                    println!("  Auth delay (91AD) — keep trying ({attempt}/20)...");
                }
                continue;
            }
            Err(e) => {
                anyhow::bail!("unexpected error: {e:?}");
            }
        }
    }

    println!("⚠️  Auth delay persists after 20 rapid attempts.");
    println!("The card may need a different key or have extensive TotFailCtr.");
    Ok(())
}
