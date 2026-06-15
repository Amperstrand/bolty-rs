//! `picc` command: read-only SDM PICC data decryption without authentication.
//!
//! Reads the NDEF file (unauthenticated), extracts the `p=` and `c=` query
//! parameters produced by the card's SDM engine, derives K1/K2 from the
//! issuer key + card UID, and decrypts/verifies the PICC data locally.
//!
//! No authentication APDUs are sent — zero risk of bricking or auth-delay.

use anyhow::Context;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::picc as picc_crypto;
use bolty_core::uid::CardUid;
use bolty_ntag::{File, Session, Transport};

use crate::common::{parse_ndef_uri, uid_to_fixed};

const DEFAULT_VERSION: u32 = 1;

pub async fn cmd_picc<T: Transport>(transport: &mut T, issuer_key: &[u8; 16]) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let mut session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID:  {}", crate::to_hex(uid_fixed));

    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        DEFAULT_VERSION,
    );
    let k1 = keys.k1.as_bytes();
    let k2 = keys.k2.as_bytes();

    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
        .context("failed to read NDEF content")?;

    let clamped = len.min(buf.len());
    let data = buf.get(..clamped).unwrap_or(&[]);
    let parsed = parse_ndef_uri(data).ok_or_else(|| {
        anyhow::anyhow!(
            "NDEF content is not a valid URI record.\n\
             Card may not be provisioned with SDM, or NDEF is empty/corrupt."
        )
    })?;
    println!("NDEF URL: {0}", parsed.url);

    let (p_hex, c_hex) = (parsed.picc_hex.as_deref(), parsed.mac_hex.as_deref());
    let (p_hex, c_hex) = match (p_hex, c_hex) {
        (Some(p), Some(c)) => (p, c),
        _ => anyhow::bail!("No p= and c= parameters found in NDEF URL"),
    };

    println!("\nExtracted SDM parameters:");
    println!("  p = {p_hex}");
    println!("  c = {c_hex}");

    match picc_crypto::picc_decrypt_p(k1, p_hex) {
        Some(picc) => {
            println!("\nPICC data (decrypted with K1):");
            println!("  UID:            {}", crate::to_hex(picc.uid));
            println!("  Read counter:   {}", picc.counter);

            let uid_match = picc.uid == uid_fixed;
            println!("  UID matches:    {}", if uid_match { "YES" } else { "NO" });

            let c_ok = picc_crypto::picc_verify_c(k2, &picc, c_hex);
            println!("  CMAC valid:     {}", if c_ok { "YES" } else { "NO" });

            println!();
            if uid_match && c_ok {
                println!("SDM verification PASSED.");
            } else if c_ok {
                println!("CMAC valid but UID mismatch (card may be cloned).");
            } else {
                println!(
                    "SDM CMAC verification FAILED.\n\
                     Possible causes: wrong issuer key, wrong key version, or corrupt data."
                );
            }
        }
        None => {
            println!("\nFailed to decrypt p= parameter (wrong issuer key or placeholder data).");
        }
    }

    Ok(())
}
