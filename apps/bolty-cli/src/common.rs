use std::time::Duration;

use ntag424::{Session, SessionError, Transport, Uid};

const AUTH_RETRY_DELAYS: &[u64] = &[2, 5];

pub(crate) fn uid_to_fixed(uid: &Uid) -> [u8; 7] {
    match uid {
        Uid::Fixed(f) => *f,
        Uid::Random(_) => [0u8; 7],
    }
}

pub(crate) fn is_auth_delay<T: std::error::Error + std::fmt::Debug>(err: &SessionError<T>) -> bool {
    matches!(
        err,
        SessionError::ErrorResponse(ntag424::types::ResponseStatus::AuthenticationDelay)
    )
}

pub(crate) fn gen_rnd_a() -> anyhow::Result<[u8; 16]> {
    let mut rnd_a = [0u8; 16];
    getrandom::fill(&mut rnd_a).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    Ok(rnd_a)
}

pub(crate) struct AuthRetry {
    attempt: usize,
}

impl AuthRetry {
    pub(crate) fn new() -> Self {
        Self { attempt: 0 }
    }

    pub(crate) fn next_delay(&mut self) -> Option<Duration> {
        let delay_secs = *AUTH_RETRY_DELAYS.get(self.attempt)?;
        self.attempt += 1;
        let total = 1 + AUTH_RETRY_DELAYS.len();
        println!(
            "  Auth delay — waiting {delay_secs}s (retry {}/{total})...",
            self.attempt
        );
        Some(Duration::from_secs(delay_secs))
    }

    pub(crate) fn exhausted_msg() -> String {
        format!(
            "authentication failed after {} attempts — auth delay persisted. \
             Wait 30s for the card to reset, then retry.",
            1 + AUTH_RETRY_DELAYS.len()
        )
    }
}

impl Default for AuthRetry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) async fn preflight_check<T: Transport>(transport: &mut T) -> anyhow::Result<[u8; 7]>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .map_err(|e| anyhow::anyhow!("pre-flight: card not responding ({e})"))?;
    let uid_fixed = uid_to_fixed(&uid);

    let version = session
        .get_version(transport)
        .await
        .map_err(|e| anyhow::anyhow!("pre-flight: cannot read card version ({e})"))?;

    if version.hw_vendor_id() != 0x04 || version.hw_type() != 0x04 {
        anyhow::bail!(
            "pre-flight: card is not NTAG424 DNA (vendor={:02X}, type={:02X}). \
             Refusing to modify non-NTAG424 card.",
            version.hw_vendor_id(),
            version.hw_type()
        );
    }

    Ok(uid_fixed)
}

pub(crate) struct NdefUri {
    pub url: String,
    pub picc_hex: Option<String>,
    pub mac_hex: Option<String>,
}

const URI_PREFIXES: &[&str] = &["", "http://www.", "https://www.", "http://", "https://"];

pub(crate) fn parse_ndef_uri(data: &[u8]) -> Option<NdefUri> {
    if data.len() < 4 {
        return None;
    }
    let nlen = usize::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
    if nlen < 5 || data.len() < 2 + nlen {
        return None;
    }
    let msg = data.get(2..2 + nlen)?;

    let flags = *msg.first()?;
    let sr = (flags & 0x10) != 0;
    let il = (flags & 0x08) != 0;

    let type_len = usize::from(*msg.get(1)?);
    let header_len = if sr { 3 } else { 6 };

    let payload_len = if sr {
        usize::from(*msg.get(2)?)
    } else {
        u32::from_be_bytes([*msg.get(2)?, *msg.get(3)?, *msg.get(4)?, *msg.get(5)?]) as usize
    };

    // Type field must be 'U' (URI) with exactly 1-byte type length.
    if type_len != 1 || *msg.get(header_len)? != b'U' {
        return None;
    }

    // Payload offset: header + type + optional ID Length field + ID field.
    let mut payload_offset = header_len + type_len;
    if il {
        let id_len = usize::from(*msg.get(payload_offset)?);
        payload_offset = payload_offset.checked_add(1)?.checked_add(id_len)?;
    }

    let payload_end = payload_offset.checked_add(payload_len)?;
    let payload = msg.get(payload_offset..payload_end)?;
    if payload.is_empty() {
        return None;
    }

    let prefix_code = usize::from(*payload.first()?);
    let prefix = URI_PREFIXES.get(prefix_code).copied().unwrap_or("");
    let uri = payload.get(1..)?;
    let uri_str = std::str::from_utf8(uri).ok()?.trim_end_matches('\0');
    let url = format!("{prefix}{uri_str}");

    let (picc_hex, mac_hex) = match bolty_core::picc::extract_p_and_c(uri_str) {
        Some((p, c)) => (Some(p.to_string()), Some(c.to_string())),
        None => (None, None),
    };

    Some(NdefUri {
        url,
        picc_hex,
        mac_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid NDEF URI record: https://abcd
    // NLEN=9, flags=D1 (MB|ME|SR|TNF=1), type_len=1, payload_len=5,
    // type='U', uri_prefix=0x04 (https://), payload="abcd"
    const MINIMAL_NDEF: &[u8] = &[
        0x00, 0x09, // NLEN = 9
        0xD1, // flags: MB=1 ME=1 CF=0 SR=1 IL=0 TNF=001
        0x01, // type length = 1
        0x05, // payload length = 5
        0x55, // type = 'U' (URI)
        0x04, // URI prefix code 4 = "https://"
        0x61, 0x62, 0x63, 0x64, // "abcd"
    ];

    const BOLTCARD_NDEF: &[u8] = &[
        0x00, 0x4F, // NLEN = 79
        0xD1, // flags
        0x01, // type length
        0x4B, // payload length = 75
        0x55, // type = 'U'
        0x04, // https://
        b'b', b'o', b'l', b't', b'c', b'a', b'r', b'd', b'p', b'o', b'c', b'.', b'p', b's', b'b',
        b't', b'.', b'm', b'e', b'/', b'?', b'p', b'=', b'A', b'B', b'C', b'D', b'E', b'F', b'0',
        b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'&', b'c', b'=', b'0', b'1',
        b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
    ];

    #[test]
    fn parse_minimal_ndef() {
        let parsed = parse_ndef_uri(MINIMAL_NDEF).unwrap();
        assert_eq!(parsed.url, "https://abcd");
        assert!(parsed.picc_hex.is_none());
        assert!(parsed.mac_hex.is_none());
    }

    #[test]
    fn parse_boltcard_ndef() {
        let parsed = parse_ndef_uri(BOLTCARD_NDEF).unwrap();
        assert!(parsed.url.starts_with("https://boltcardpoc.psbt.me/?p="));
        assert_eq!(
            parsed.picc_hex.as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789")
        );
        assert_eq!(parsed.mac_hex.as_deref(), Some("0123456789ABCDEF"));
    }

    #[test]
    fn parse_empty_ndef() {
        assert!(parse_ndef_uri(&[0x00, 0x00]).is_none());
    }

    #[test]
    fn parse_short_ndef() {
        assert!(parse_ndef_uri(&[0x00, 0x01, 0xD1]).is_none());
    }

    #[test]
    fn parse_non_uri_ndef() {
        let data = &[
            0x00, 0x05, 0xD1, 0x01, 0x01, 0x54, // type = 'T' (Text), not 'U'
            0x02, 0x65, 0x6e, 0x68, 0x69,
        ];
        assert!(parse_ndef_uri(data).is_none());
    }

    #[test]
    fn parse_wrong_prefix_code() {
        let data = &[
            0x00, 0x07, 0xD1, 0x01, 0x03, 0x55, 0xFF, // invalid prefix code
            b'x', b'y',
        ];
        let parsed = parse_ndef_uri(data).unwrap();
        assert_eq!(parsed.url, "xy");
    }

    #[test]
    fn parse_long_record_non_sr() {
        let mut data = vec![0x00, 0x00]; // NLEN placeholder
        data.push(0xC1); // flags: SR=0 (long record)
        data.push(0x01); // type length
        data.extend_from_slice(&100u32.to_be_bytes()); // payload length = 100
        data.push(0x55); // type = 'U'
        data.push(0x04); // https://
        data.extend(std::iter::repeat(b'x').take(99)); // 99 more payload bytes
        let nlen = (data.len() - 2) as u16;
        data[0..2].copy_from_slice(&nlen.to_be_bytes());
        let parsed = parse_ndef_uri(&data).unwrap();
        assert!(parsed.url.starts_with("https://"));
        assert_eq!(parsed.url.len(), 8 + 100 - 1); // prefix + payload minus prefix code byte
    }

    #[test]
    fn parse_with_id_length_present() {
        let data = vec![
            0x00, 0x0A, // NLEN = 10
            0xD9, // flags: SR=1, IL=1 (ID length present)
            0x01, // type length
            0x04, // payload length
            0x55, // type = 'U'
            0x01, // ID length = 1
            0x42, // ID = 'B'
            0x04, // https://
            b'x', b'y', b'z',
        ];
        let parsed = parse_ndef_uri(&data).unwrap();
        assert_eq!(parsed.url, "https://xyz");
        assert_eq!(data.len(), 12);
    }

    #[test]
    fn parse_truncated_payload() {
        let data = &[
            0x00, 0x10, // NLEN = 16 (claims more than available)
            0xD1, 0x01, 0x20, 0x55, 0x04, b'h', b'e', b'l', b'l', b'o',
        ];
        // NLEN says 16 but only 9 bytes of message follow
        assert!(parse_ndef_uri(data).is_none());
    }

    #[test]
    fn parse_sdm_url_config_ndef_template() {
        use ntag424::KeyNumber;
        use ntag424::sdm::{SdmUrlOptions, sdm_url_config};
        use ntag424::types::file_settings::CryptoMode;

        let opts = SdmUrlOptions {
            picc_key: KeyNumber::Key1,
            mac_key: KeyNumber::Key2,
            ..SdmUrlOptions::new()
        };
        let url = "https://card.bolt.local/lnurl?[[p={picc:uid+ctr}&cmac={mac}";
        let plan = sdm_url_config(url, CryptoMode::Aes, opts).unwrap();

        let parsed = parse_ndef_uri(&plan.ndef_bytes)
            .expect("parse_ndef_uri should handle sdm_url_config output");
        assert!(
            parsed.url.contains("card.bolt.local"),
            "URL should contain domain, got: {}",
            parsed.url
        );
    }
}
