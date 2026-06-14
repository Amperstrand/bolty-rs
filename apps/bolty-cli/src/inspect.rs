use anyhow::Context;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::picc as picc_crypto;
use bolty_core::uid::CardUid;
use ntag424::{File, KeyNumber, Session, Transport};
use std::time::Duration;

use crate::common::{gen_rnd_a, is_auth_delay, uid_to_fixed};

const URI_PREFIXES: &[&str] = &["", "http://www.", "https://www.", "http://", "https://"];

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

struct NdefUri {
    url: String,
    picc_hex: Option<String>,
    mac_hex: Option<String>,
}

fn parse_ndef_uri(data: &[u8]) -> Option<NdefUri> {
    if data.len() < 9 {
        return None;
    }
    let nlen = usize::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
    if nlen < 7 || 2 + nlen > data.len() {
        return None;
    }
    let msg = data.get(2..2 + nlen)?;

    let flags = *msg.first()?;
    let sr = (flags & 0x10) != 0;
    let il = (flags & 0x08) != 0;

    let type_len = usize::from(*msg.get(1)?);
    let payload_len = if sr {
        usize::from(*msg.get(2)?)
    } else {
        u32::from_be_bytes([*msg.get(2)?, *msg.get(3)?, *msg.get(4)?, *msg.get(5)?]) as usize
    };

    let header_len = if sr { 3 } else { 6 };
    let mut offset = header_len + type_len;
    if il {
        offset += 1;
    }

    let payload = msg.get(offset..offset + payload_len)?;

    if type_len != 1 || *msg.get(3)? != b'U' {
        return None;
    }

    let prefix_code = usize::from(*payload.first()?);
    let prefix = URI_PREFIXES.get(prefix_code).copied().unwrap_or("");
    let uri = payload.get(1..)?;
    let uri_str = std::str::from_utf8(uri).ok()?.trim_end_matches('\0');
    let url = format!("{prefix}{uri_str}");

    let (picc_hex, mac_hex) = extract_sdm_params(uri_str);

    Some(NdefUri {
        url,
        picc_hex,
        mac_hex,
    })
}

fn extract_sdm_params(uri: &str) -> (Option<String>, Option<String>) {
    let mut p = None;
    let mut c = None;
    for segment in uri.split(['?', '&', '#']) {
        if let Some(val) = segment.strip_prefix("p=") {
            p = Some(val.to_string());
        } else if let Some(val) = segment.strip_prefix("c=") {
            c = Some(val.to_string());
        }
    }
    (p, c)
}

pub async fn cmd_url<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let mut session = Session::default();
    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
        .context("failed to read NDEF")?;

    let clamped = len.min(buf.len());
    let data = buf.get(..clamped).unwrap_or(&[]);
    let parsed = parse_ndef_uri(data).context("NDEF content is not a valid URI record")?;
    println!("{}", parsed.url);
    Ok(())
}

pub async fn cmd_inspect<T: Transport>(
    transport: &mut T,
    issuer_key: Option<[u8; 16]>,
    version: u8,
    verbose: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let mut session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("UID: {}", crate::to_hex(uid_fixed));

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

                if let Some(parsed) = parse_ndef_uri(&buf[..clamped]) {
                    println!("\nNDEF URL: {}", parsed.url);

                    if let Some(ref issuer_key) = issuer_key {
                        let keys = BoltcardDeterministicDeriver::derive_keys(
                            issuer_key,
                            CardUid::new(uid_fixed),
                            version as u32,
                        );
                        if verbose {
                            println!("\nDerived keys (version {version}):");
                            println!("  K0: {}", crate::to_hex(keys.k0.as_bytes()));
                            println!("  K1: {}", crate::to_hex(keys.k1.as_bytes()));
                            println!("  K2: {}", crate::to_hex(keys.k2.as_bytes()));
                        }

                        decrypt_and_display_sdm(keys.k1.as_bytes(), keys.k2.as_bytes(), &parsed);

                        authenticate_and_verify(transport, keys.k0.as_bytes(), verbose).await;
                    }
                }
            }
        }
        Err(e) => println!("NDEF content: (unreadable: {e})"),
    }

    Ok(())
}

fn decrypt_and_display_sdm(k1: &[u8; 16], k2: &[u8; 16], parsed: &NdefUri) {
    let Some(ref p_hex) = parsed.picc_hex else {
        return;
    };
    let Some(ref c_hex) = parsed.mac_hex else {
        return;
    };

    match picc_crypto::picc_decrypt_p(k1, p_hex) {
        Some(picc) => {
            println!(
                "\nSDM PICC decrypted: UID={} counter={} CMAC_valid={}",
                crate::to_hex(picc.uid),
                picc.counter,
                picc_crypto::picc_verify_c(k2, &picc, c_hex)
            );
        }
        None => println!("\nSDM PICC decryption failed (wrong K1?)"),
    }
}

async fn authenticate_and_verify<T: Transport>(transport: &mut T, k0: &[u8; 16], verbose: bool)
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let rnd_a = match gen_rnd_a() {
        Ok(r) => r,
        Err(e) => {
            println!("\nK0 auth: RNG failed: {e}");
            return;
        }
    };

    match Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, k0, rnd_a)
        .await
    {
        Ok(_) => {
            println!("K0 auth: SUCCESS");
            if verbose {
                println!("  (use `keyver` command for authenticated file settings read)");
            }
        }
        Err(e) if is_auth_delay(&e) => {
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!("K0 auth: delayed — retry later");
        }
        Err(e) => {
            println!("K0 auth: FAILED ({e})");
        }
    }
}
