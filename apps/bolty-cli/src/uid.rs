//! UID acquisition with transport-diverse fallback.
//!
//! Some transports (the nucula CCID broker) do not implement the pcsc
//! GET-DATA pseudo-APDU (FF CA) that `Session::get_selected_uid` uses.
//! Commands that genuinely need the UID can supply it out-of-band via
//! `BOLTY_UID_FALLBACK=<14-hex>`; commands that only display it can use
//! a placeholder. One helper, three documented behaviors, replacing the
//! three hand-rolled variants (2026-10-23 session).

use bolty_ntag::{Session, Transport};

/// How to handle an unreadable UID.
pub enum UidFallback {
    /// Substitute a display placeholder and continue.
    Placeholder,
    /// Read BOLTY_UID_FALLBACK=<14-hex>; bail if unset/invalid.
    EnvOrBail,
}

/// Read the card UID, falling back per `mode` when the transport cannot
/// supply it (nucula broker). Returns the UID as a lowercase hex string.
pub async fn uid_or_fallback<T: Transport>(
    transport: &mut T,
    mode: UidFallback,
) -> anyhow::Result<String>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    match Session::default().get_selected_uid(transport).await {
        Ok(uid) => Ok(crate::to_hex(uid.as_ref())),
        Err(_) => match mode {
            UidFallback::Placeholder => Ok("(unreadable via this transport)".to_string()),
            UidFallback::EnvOrBail => match std::env::var("BOLTY_UID_FALLBACK") {
                Ok(hex) if hex.len() == 14 => Ok(hex.to_ascii_lowercase()),
                _ => anyhow::bail!(
                    "UID unreadable via this transport — set BOLTY_UID_FALLBACK=<14-hex>"
                ),
            },
        },
    }
}

/// Parse a 14-char hex string into the fixed 7-byte array commands need
/// for key derivation.
#[allow(dead_code)] // keyver uses its own inline conversion; this is the
// public helper for future callers (diagnose, etc.)
pub fn uid_hex_to_fixed(hex: &str) -> anyhow::Result<[u8; 7]> {
    let bytes = hex.as_bytes();
    let mut out = [0u8; 7];
    let pairs: Vec<&[u8]> = (0..7).filter_map(|i| bytes.get(i * 2..i * 2 + 2)).collect();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        let hex_pair =
            std::str::from_utf8(pair).map_err(|_| anyhow::anyhow!("bad fallback hex"))?;
        *slot =
            u8::from_str_radix(hex_pair, 16).map_err(|_| anyhow::anyhow!("bad fallback hex"))?;
    }
    Ok(out)
}
