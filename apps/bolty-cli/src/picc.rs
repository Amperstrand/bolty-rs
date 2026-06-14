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
use ntag424::{File, Session, Transport};

use crate::common::uid_to_fixed;

/// Standard Bolt Card key version (matches `DeriveKeys` default).
const DEFAULT_VERSION: u32 = 1;

pub async fn cmd_picc<T: Transport>(transport: &mut T, issuer_key: &[u8; 16]) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let mut session = Session::default();

    // 1. Read card UID (no authentication needed).
    let uid = session
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    println!("Card UID:  {}", crate::to_hex(uid_fixed));

    // 2. Derive K1/K2 from issuer key + UID.
    //    K1 = AES-CMAC(issuer_key, TAG_K1)  — independent of version.
    //    K2 = AES-CMAC(card_key, TAG_K2)    — depends on version (default 1).
    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        DEFAULT_VERSION,
    );
    let k1 = keys.k1.as_bytes();
    let k2 = keys.k2.as_bytes();

    // 3. Read NDEF content without authentication.
    //    The card's SDM engine fills in p= and c= on read regardless of auth.
    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
        .context("failed to read NDEF content")?;

    // NDEF Type 4: first 2 bytes = NLEN (big-endian length of NDEF message).
    // Truncate to actual content to avoid picking up null-byte padding.
    let clamped = len.min(buf.len());
    let ndef_end = if clamped >= 2 {
        let nlen = (buf[0] as usize) * 256 + buf[1] as usize;
        (nlen + 2).min(clamped)
    } else {
        clamped
    };
    let ndef_str = String::from_utf8_lossy(buf.get(2..ndef_end).unwrap_or(&[]));
    println!("NDEF ({clamped} bytes): {ndef_str}");

    // 4. Extract p= and c= from the SDM-augmented URL.
    let (p_hex, c_hex) = picc_crypto::extract_p_and_c(&ndef_str).ok_or_else(|| {
        anyhow::anyhow!(
            "No p= and c= parameters found in NDEF content.\n\
             Card may not be provisioned with SDM, or NDEF is empty/corrupt."
        )
    })?;

    println!("\nExtracted SDM parameters:");
    println!("  p = {p_hex}");
    println!("  c = {c_hex}");

    // 5. Decrypt p= with K1 (AES-128-CBC, zero IV).
    match picc_crypto::picc_decrypt_p(k1, p_hex) {
        Some(picc) => {
            println!("\nPICC data (decrypted with K1):");
            println!("  UID:            {}", crate::to_hex(picc.uid));
            println!("  Read counter:   {}", picc.counter);

            let uid_match = picc.uid == uid_fixed;
            println!("  UID matches:    {}", if uid_match { "YES" } else { "NO" });

            // 6. Verify c= with K2 (AES-CMAC over SV2).
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
