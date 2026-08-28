use anyhow::{Context, bail};
use bolty_core::provenance::KeyProvenance;
use bolty_core::secret::{AesKey, CardKeys};
use bolty_ntag::Transport;
use serde::Deserialize;
use std::io::Read;

use crate::burn::{BurnOptions, burn_card};

/// Wire format of the proxy's `GET /new?a=<one-time-code>` response
/// (boltcard `new_card_request.go`, protocol "create_bolt_card_response" v2).
#[derive(Debug, Deserialize)]
struct ProvisionResponse {
    protocol_name: String,
    protocol_version: i64,
    #[allow(dead_code)]
    card_name: String,
    lnurlw_base: String,
    k0: String,
    k1: String,
    k2: String,
    k3: String,
    k4: String,
    uid_privacy: String,
}

/// Fetched key set ready to burn. `Debug` is safe: `CardKeys` redacts key
/// material.
#[derive(Debug)]
pub struct ProvisionKeys {
    pub keys: CardKeys,
    pub url: String,
    pub uid_privacy: bool,
}

pub fn parse_provision_response(body: &str) -> anyhow::Result<ProvisionKeys> {
    let resp: ProvisionResponse = serde_json::from_str(body).with_context(|| {
        // The proxy reports card-flow errors as plain text (HTTP 200) —
        // surface it instead of a bare JSON syntax error.
        let excerpt: String = body.chars().take(120).collect();
        format!("response is not create_bolt_card_response JSON: {excerpt:?}")
    })?;

    if resp.protocol_name != "create_bolt_card_response" {
        bail!(
            "unexpected protocol_name {:?} — not a bolt-card provisioning response",
            resp.protocol_name
        );
    }
    if resp.protocol_version != 2 {
        bail!(
            "unsupported protocol_version {} (expected 2)",
            resp.protocol_version
        );
    }

    let parse = |hex: &str, field: &str| {
        AesKey::from_hex(hex.trim()).with_context(|| format!("invalid {field} from proxy"))
    };
    let keys = CardKeys {
        k0: parse(&resp.k0, "k0")?,
        k1: parse(&resp.k1, "k1")?,
        k2: parse(&resp.k2, "k2")?,
        k3: parse(&resp.k3, "k3")?,
        k4: parse(&resp.k4, "k4")?,
    };

    let base = resp.lnurlw_base.trim();
    if !(base.starts_with("lnurlw://") || base.starts_with("https://")) || base.contains('{') {
        bail!("suspicious lnurlw_base from proxy: {base:?}");
    }
    let url = format!("{base}?p={{picc:uid+ctr}}&c={{mac}}");

    let uid_privacy = matches!(resp.uid_privacy.trim(), "true" | "TRUE" | "True");

    Ok(ProvisionKeys {
        keys,
        url,
        uid_privacy,
    })
}

pub fn fetch_provision_keys(proxy_base: &str, code: &str) -> anyhow::Result<ProvisionKeys> {
    let base = proxy_base.trim_end_matches('/');
    if code.is_empty() || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("one-time code must be non-empty alphanumeric");
    }
    let url = format!("{base}/new?a={code}");

    let response = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|e| anyhow::anyhow!("request to {url} failed: {e}"))?;

    let mut body = String::new();
    response
        .into_reader()
        .take(64 * 1024)
        .read_to_string(&mut body)
        .with_context(|| "reading provisioning response")?;

    parse_provision_response(&body)
}

/// Burn a fetched key set. The one-time code was consumed by the fetch that
/// produced `provisioned`; this runs the full card burn with ProxyIssued
/// provenance.
pub async fn burn_provisioned<T: Transport>(
    transport: &mut T,
    provisioned: &ProvisionKeys,
    verbose: bool,
    confirm_uid: Option<&[u8; 7]>,
    force: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    if provisioned.uid_privacy {
        // BOLT_PRIV: | best          | no        | no           |

        // uid_privacy=true requests "best" privacy (no static id, no UID
        // plaintext) — not yet applied by this burner, hence the warning.
        println!(
            "  ⚠ uid_privacy=true requested by proxy — this burner does not yet apply UID-privacy mode"
        );
    }

    burn_card(
        transport,
        &provisioned.keys,
        &provisioned.url,
        BurnOptions {
            version: 1,
            verbose,
            dry_run: false,
            confirm_uid,
            force,
            provenance: KeyProvenance::ProxyIssued,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "protocol_name": "create_bolt_card_response",
        "protocol_version": 2,
        "card_name": "test_card_1",
        "lnurlw_base": "lnurlw://proxy.example.com/ln",
        "k0": "000102030405060708090a0b0c0d0e0f",
        "k1": "101112131415161718191a1b1c1d1e1f",
        "k2": "202122232425262728292a2b2c2d2e2f",
        "k3": "00112233445566778899aabbccddeeff",
        "k4": "ffeeddccbbaa99887766554433221100",
        "uid_privacy": "false"
    }"#;

    #[test]
    fn parses_valid_response() {
        let p = parse_provision_response(SAMPLE).unwrap();
        assert_eq!(
            p.url,
            "lnurlw://proxy.example.com/ln?p={picc:uid+ctr}&c={mac}"
        );
        assert!(!p.uid_privacy);
        assert_eq!(p.keys.k0.as_bytes()[0], 0x00);
        assert_eq!(p.keys.k0.as_bytes()[15], 0x0f);
    }

    #[test]
    fn rejects_wrong_protocol_name() {
        let bad = SAMPLE.replace("create_bolt_card_response", "something_else");
        assert!(parse_provision_response(&bad).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let bad = SAMPLE.replace("\"protocol_version\": 2", "\"protocol_version\": 3");
        assert!(parse_provision_response(&bad).is_err());
    }

    #[test]
    fn rejects_bad_key_hex() {
        let bad = SAMPLE.replace(
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0z",
        );
        let err = parse_provision_response(&bad).unwrap_err().to_string();
        assert!(err.contains("k0"), "error should name the field: {err}");
    }

    #[test]
    fn rejects_suspicious_base() {
        let bad = SAMPLE.replace("lnurlw://proxy.example.com/ln", "http://x/{evil}");
        assert!(parse_provision_response(&bad).is_err());
    }

    #[test]
    fn parses_uid_privacy_true() {
        let good = SAMPLE.replace("\"uid_privacy\": \"false\"", "\"uid_privacy\": \"true\"");
        assert!(parse_provision_response(&good).unwrap().uid_privacy);
    }

    #[test]
    fn rejects_plain_text_error_body() {
        let err = parse_provision_response(
            "one time code was used or card was wiped or card does not exist",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not create_bolt_card_response JSON"),
            "error should reject plain-text body: {msg}"
        );
        assert!(
            msg.contains("one time code was used"),
            "error should surface the proxy's message: {msg}"
        );
    }
}
