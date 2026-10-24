//! Persisted wifi credentials — pure encode/decode seam (bolty #143/#144).
//!
//! The ESP32 frontends store the station credentials as two NVS blobs
//! under the keys below; this module owns the blob↔string semantics so
//! they are host-testable: the firmware layer only supplies raw bytes
//! read from NVS and consumes the decoded pair. A truncated or missing
//! pair is treated as absent (autoconnect falls back to "no stored
//! credentials"), and non-UTF-8 or over-length blobs decode as absent
//! rather than poisoning the boot path.

use crate::config::{WifiPasswordString, WifiSsidString};

/// NVS key holding the SSID blob.
pub const KEY_SSID: &str = "ssid";
/// NVS key holding the password blob.
pub const KEY_PASS: &str = "pass";

/// Decode one stored credential blob. Returns `None` for non-UTF-8 data
/// or a blob that exceeds the string capacity — both mean "absent".
pub fn decode_creds_blob<const N: usize>(bytes: &[u8]) -> Option<heapless::String<N>> {
    heapless::String::try_from(core::str::from_utf8(bytes).ok()?).ok()
}

/// Decode a stored (ssid, password) pair. `None` for either blob —
/// missing, non-UTF-8, or over-length — makes the whole pair absent:
/// credentials are only usable when both halves survived persistence.
pub fn decode_creds_pair(
    ssid_bytes: Option<&[u8]>,
    pass_bytes: Option<&[u8]>,
) -> Option<(WifiSsidString, WifiPasswordString)> {
    let ssid = decode_creds_blob(ssid_bytes?)?;
    let password = decode_creds_blob(pass_bytes?)?;
    Some((ssid, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssid(bytes: &[u8]) -> Option<WifiSsidString> {
        decode_creds_blob(bytes)
    }

    fn pass(bytes: &[u8]) -> Option<WifiPasswordString> {
        decode_creds_blob(bytes)
    }

    #[test]
    fn keys_are_the_persisted_contract() {
        // The NVS key names are the on-flash contract with earlier
        // firmware: renaming them silently orphans stored credentials.
        assert_eq!(KEY_SSID, "ssid");
        assert_eq!(KEY_PASS, "pass");
    }

    #[test]
    fn roundtrip_ascii() {
        let (decoded_ssid, decoded_pass) =
            decode_creds_pair(Some(b"bench-2g"), Some(b"hunter2")).unwrap();
        assert_eq!(decoded_ssid.as_str(), "bench-2g");
        assert_eq!(decoded_pass.as_str(), "hunter2");
    }

    #[test]
    fn roundtrip_at_capacity() {
        let max_ssid = "s".repeat(32);
        let max_pass = "p".repeat(64);
        let (decoded_ssid, decoded_pass) =
            decode_creds_pair(Some(max_ssid.as_bytes()), Some(max_pass.as_bytes())).unwrap();
        assert_eq!(decoded_ssid.len(), 32);
        assert_eq!(decoded_pass.len(), 64);
    }

    #[test]
    fn empty_blobs_decode_to_empty_strings() {
        // Zero-length blobs are valid NVS entries; empty strings round-trip.
        let (decoded_ssid, decoded_pass) = decode_creds_pair(Some(b""), Some(b"")).unwrap();
        assert_eq!(decoded_ssid.as_str(), "");
        assert_eq!(decoded_pass.as_str(), "");
    }

    #[test]
    fn over_length_blob_is_absent() {
        let too_long_ssid = "s".repeat(33);
        let too_long_pass = "p".repeat(65);
        assert_eq!(ssid(too_long_ssid.as_bytes()), None);
        assert_eq!(pass(too_long_pass.as_bytes()), None);
        // get_blob would fail with INVALID_LENGTH before ever reaching
        // the decoder; the pure seam enforces the same boundary.
        assert_eq!(
            decode_creds_pair(Some(too_long_ssid.as_bytes()), Some(b"x")),
            None
        );
    }

    #[test]
    fn non_utf8_blob_is_absent() {
        let invalid = [0xFF, 0xFE];
        assert_eq!(ssid(&invalid), None);
        assert_eq!(pass(&invalid), None);
        assert_eq!(decode_creds_pair(Some(&invalid), Some(b"x")), None);
        assert_eq!(decode_creds_pair(Some(b"x"), Some(&invalid)), None);
    }

    #[test]
    fn truncated_pair_is_absent() {
        // "A truncated or missing pair is treated as absent": either
        // half missing (power loss between the two set_blob calls)
        // must not produce a half-pair.
        assert_eq!(decode_creds_pair(None, Some(b"hunter2")), None);
        assert_eq!(decode_creds_pair(Some(b"bench-2g"), None), None);
        assert_eq!(decode_creds_pair(None, None), None);
    }

    #[test]
    fn utf8_multibyte_roundtrip() {
        // SSIDs are UTF-8 in the wild; multibyte content must survive
        // within the byte capacity (32 bytes = 10 × U+1F98B + 2 spare).
        let multibyte = "\u{1F98B}".repeat(8); // 4 bytes each = 32
        assert_eq!(ssid(multibyte.as_bytes()).unwrap().as_str(), multibyte);
        let (decoded_ssid, _) = decode_creds_pair(Some(multibyte.as_bytes()), Some(b"p")).unwrap();
        assert_eq!(decoded_ssid.as_str(), multibyte);
    }
}
