use anyhow::Context;
use ntag424::{File, Session, Transport};

use crate::common::uid_to_fixed;

pub async fn cmd_uid<T: Transport>(transport: &mut T) -> anyhow::Result<[u8; 7]>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("UID: {}", crate::to_hex(uid_fixed));
    Ok(uid_fixed)
}

pub async fn cmd_inspect<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let mut session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    println!("UID: {}", crate::to_hex(uid.as_ref()));

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
            // SAFETY: clamped via .min(buf.len()).
            #[allow(clippy::indexing_slicing)]
            {
                let clamped = len.min(buf.len());
                println!(
                    "NDEF content ({} bytes): {}",
                    clamped,
                    crate::to_hex(&buf[..clamped])
                );
                if let Ok(s) = std::str::from_utf8(&buf[..clamped]) {
                    println!("NDEF (text): {s}");
                }
            }
        }
        Err(e) => println!("NDEF content: (unreadable: {e})"),
    }

    Ok(())
}
