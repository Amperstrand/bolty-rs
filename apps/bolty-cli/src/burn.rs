use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::{BoltcardDeterministicDeriver, CardKeySet};
use bolty_core::provenance::KeyProvenance;
use bolty_core::secret::{AesKey, CardKeys};
use bolty_core::uid::CardUid;
use bolty_ntag::{
    CryptoMode, KeyNumber, SdmUrlOptions, Session, Transport, sdm_url_config,
    standardize_url_template,
};

use crate::audit;
use crate::common::{AuthRetry, gen_rnd_a, is_auth_delay, map_ntag_error, record_auth_failure};

#[allow(clippy::too_many_arguments)]
pub async fn cmd_burn<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    url: &str,
    version: u8,
    verbose: bool,
    dry_run: bool,
    confirm_uid: Option<&[u8; 7]>,
    force: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid_fixed = bolty_ntag::preflight(transport)
        .await
        .map_err(map_ntag_error)?;
    println!("Card UID: {}", crate::to_hex(uid_fixed));

    if let Some(expected) = confirm_uid {
        if uid_fixed != *expected {
            anyhow::bail!(
                "UID mismatch: expected {}, got {} — refusing to burn wrong card",
                crate::to_hex(expected),
                crate::to_hex(uid_fixed),
            );
        }
        println!("  ✓ UID confirmed");
    }

    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        version as u32,
    );
    if verbose || dry_run {
        print_derived_keys(&keys, version);
    }

    if dry_run {
        let sdm_opts = SdmUrlOptions {
            picc_key: KeyNumber::Key1,
            mac_key: KeyNumber::Key2,
            ..SdmUrlOptions::new()
        };
        let standardized = standardize_url_template(url);
        let ndef_size = sdm_url_config(&standardized, CryptoMode::Aes, sdm_opts)
            .map_err(|e| anyhow::anyhow!("SDM URL config error: {e}"))?
            .ndef_bytes
            .len();

        println!("\n=== DRY RUN — no card modifications ===");
        println!("URL:       {url}");
        println!("Version:   {version}");
        println!("NDEF size: {ndef_size} bytes");
        println!("\nPlanned steps:");
        println!("  [1] Authenticate (factory K0 or derived K0)");
        println!("  [2] Write NDEF template + verify readback");
        println!("  [3] Configure SDM file settings + verify");
        println!("  [4] Install K1");
        println!("  [5] Install K2");
        println!("  [6] Install K3");
        println!("  [7] Install K4, then K0 (master)");
        println!("  Post:  Re-authenticate with new K0 + verify SDM");
        println!("\nNo APDUs sent. Card unchanged.");
        return Ok(());
    }

    if !force && (!url.contains("{picc") || !url.contains("{mac}")) {
        anyhow::bail!(
            "URL must contain {{picc}} and {{mac}} placeholders for SDM.\n\
             Example: https://example.com/?p={{picc:uid+ctr}}&c=[{{mac}}\n\
             Got: {url}\n\
             Use --force to override this check."
        );
    }

    if !force {
        println!("[0/7] Checking card state...");
    } else {
        println!("[0/7] Safety checks bypassed (--force)");
    }
    if !force {
        let factory_like = {
            let mut retry = AuthRetry::new();
            loop {
                let rnd_a = gen_rnd_a()?;
                match Session::default()
                    .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
                    .await
                {
                    Ok(_) => break true,
                    Err(e) if is_auth_delay(&e) => match retry.next_delay() {
                        Some(d) => {
                            tokio::time::sleep(d).await;
                        }
                        None => {
                            anyhow::bail!(
                                "card is in AUTH_DELAY state.\n\
                                 The 'keep trying' approach was exhausted.\n\
                                 Use: bolty-cli try-key --key 00000000000000000000000000000000\n\
                                 Then retry the burn."
                            );
                        }
                    },
                    Err(_) => break false,
                }
            }
        };
        if factory_like {
            println!("  Card is BLANK (factory keys).");
        } else {
            println!("  Card is PROVISIONED — will attempt re-burn with derived K0.");
        }
    }

    // --- Probe auth: determine current_key and previous_keys ---
    // Try factory K0 first (fresh card), then derived K0 (re-burn).
    // This probe is separate from the library's internal auth — the card supports re-auth.
    println!("[1/7] Authenticating...");
    let (current_key, previous_keys, provenance): (AesKey, CardKeys, KeyProvenance) = {
        let factory_works = {
            let mut retry = AuthRetry::new();
            loop {
                let rnd_a = gen_rnd_a()?;
                match Session::default()
                    .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
                    .await
                {
                    Ok(_) => break true,
                    Err(e) if is_auth_delay(&e) => match retry.next_delay() {
                        Some(d) => {
                            tokio::time::sleep(d).await;
                        }
                        None => anyhow::bail!("{}", AuthRetry::exhausted_msg()),
                    },
                    Err(_) => {
                        record_auth_failure();
                        break false;
                    }
                }
            }
        };

        if factory_works {
            println!("  Authenticated with factory K0");
            audit::log_event_with_provenance(
                "burn: authenticated with factory K0",
                Some(KeyProvenance::FactoryDefault),
            );
            (
                AesKey::new(FACTORY_KEY),
                CardKeys {
                    k0: AesKey::new(FACTORY_KEY),
                    k1: AesKey::new(FACTORY_KEY),
                    k2: AesKey::new(FACTORY_KEY),
                    k3: AesKey::new(FACTORY_KEY),
                    k4: AesKey::new(FACTORY_KEY),
                },
                KeyProvenance::FactoryDefault,
            )
        } else {
            println!("  Factory K0 rejected, trying derived K0...");
            let mut retry = AuthRetry::new();
            let derived_works = loop {
                let rnd_a = gen_rnd_a()?;
                match Session::default()
                    .authenticate_aes(transport, KeyNumber::Key0, keys.k0.as_bytes(), rnd_a)
                    .await
                {
                    Ok(_) => break true,
                    Err(e) if is_auth_delay(&e) => match retry.next_delay() {
                        Some(d) => {
                            tokio::time::sleep(d).await;
                        }
                        None => anyhow::bail!("{}", AuthRetry::exhausted_msg()),
                    },
                    Err(_) => {
                        record_auth_failure();
                        break false;
                    }
                }
            };

            if derived_works {
                println!("  Authenticated with derived K0 (re-burn)");
                audit::log_event_with_provenance(
                    &format!("burn: authenticated with derived K0 v{version}"),
                    Some(KeyProvenance::DerivedIssuer { version }),
                );
                let derived_keyset = CardKeys {
                    k0: keys.k0.clone(),
                    k1: keys.k1.clone(),
                    k2: keys.k2.clone(),
                    k3: keys.k3.clone(),
                    k4: keys.k4.clone(),
                };
                (
                    keys.k0.clone(),
                    derived_keyset,
                    KeyProvenance::DerivedIssuer { version },
                )
            } else {
                anyhow::bail!(
                    "authentication failed with both factory and derived K0 — \
                     card may use a different issuer key"
                );
            }
        }
    };

    // --- Delegate to library: it handles NDEF write, SDM config, key install, verification ---
    let new_keys = CardKeys {
        k0: keys.k0.clone(),
        k1: keys.k1.clone(),
        k2: keys.k2.clone(),
        k3: keys.k3.clone(),
        k4: keys.k4.clone(),
    };

    let params = bolty_ntag::BurnParams {
        lnurl: url,
        keys: new_keys,
        key_version: version,
        current_key,
        previous_keys,
    };

    let rnd_a = AesKey::new(gen_rnd_a()?);
    println!("\nBurning card...");
    audit::log_event_with_provenance(
        &format!(
            "burn: starting — UID={}, version={version}, url={url}",
            crate::to_hex(uid_fixed)
        ),
        Some(provenance),
    );
    if let Err(e) = bolty_ntag::burn(transport, &params, rnd_a).await {
        audit::log_event_with_provenance("burn: FAILED", Some(provenance));
        return Err(map_ntag_error(e));
    }

    audit::log_event_with_provenance(
        &format!("burn: SUCCESS — K0 v{version}, K1-K4 installed"),
        Some(provenance),
    );
    println!("\n✅ Card burned and verified successfully!");
    Ok(())
}

fn print_derived_keys(keys: &CardKeySet, version: u8) {
    println!("Derived keys (version {version}):");
    println!("  cardKey: {}", crate::to_hex(keys.card_key.as_bytes()));
    println!("  K0:      {}", crate::to_hex(keys.k0.as_bytes()));
    println!("  K1:      {}", crate::to_hex(keys.k1.as_bytes()));
    println!("  K2:      {}", crate::to_hex(keys.k2.as_bytes()));
    println!("  K3:      {}", crate::to_hex(keys.k3.as_bytes()));
    println!("  K4:      {}", crate::to_hex(keys.k4.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_preserves_factory_card_state() {
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";

        let keys_before = *transport.keys();
        let ndef_before = transport.ndef().to_vec();
        let settings_before = transport.file_settings().to_vec();

        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            true,
            None,
            false,
        )
        .await;
        assert!(result.is_ok(), "dry-run should succeed: {:?}", result.err());

        assert_eq!(
            transport.keys(),
            &keys_before,
            "keys must not change during dry-run"
        );
        assert_eq!(
            transport.ndef(),
            &ndef_before[..],
            "NDEF must not change during dry-run"
        );
        assert_eq!(
            transport.file_settings(),
            &settings_before[..],
            "file settings must not change during dry-run"
        );
    }

    #[tokio::test]
    async fn confirm_uid_rejects_mismatch() {
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        let wrong_uid = [0xFFu8; 7];

        let keys_before = transport.keys().clone();

        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            Some(&wrong_uid),
            false,
        )
        .await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("UID mismatch"),
            "error should mention UID mismatch: {msg}"
        );

        assert_eq!(
            transport.keys(),
            &keys_before,
            "no keys should change on UID mismatch"
        );
    }

    #[tokio::test]
    async fn confirm_uid_accepts_match() {
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        let correct_uid = crate::mock_transport::UID;

        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            true,
            Some(&correct_uid),
            false,
        )
        .await;

        assert!(
            result.is_ok(),
            "dry-run with correct UID should pass: {:?}",
            result.err()
        );
    }

    // Audit-path tests across modules share one mutable global; the centralized
    // AUDIT_TEST_MUTEX serializes set→write→read so each test sees its own log.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn burn_logs_factory_provenance() {
        let _guard = crate::audit::AUDIT_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut tmp_path = std::env::temp_dir();
        tmp_path.push(format!("bolty-audit-burn-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&tmp_path);
        crate::audit::set_audit_log_path(tmp_path.clone());

        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";

        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await;
        assert!(
            result.is_ok(),
            "factory burn should succeed: {:?}",
            result.err()
        );

        let content = std::fs::read_to_string(&tmp_path).unwrap_or_else(|_| String::new());
        assert!(
            content.contains("[provenance=FactoryDefault]"),
            "factory-path burn audit must contain [provenance=FactoryDefault], got: {content:?}"
        );
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn burn_logs_derived_provenance() {
        let _guard = crate::audit::AUDIT_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut tmp_path = std::env::temp_dir();
        tmp_path.push(format!("bolty-audit-burn-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&tmp_path);
        crate::audit::set_audit_log_path(tmp_path.clone());

        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0x42u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";

        // First burn on factory card installs derived v1 keys
        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await;
        assert!(
            result.is_ok(),
            "first burn should succeed: {:?}",
            result.err()
        );

        let _ = std::fs::remove_file(&tmp_path);

        // Re-burn: card now has derived K0 v1, so derived auth path is taken
        let result = cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await;
        assert!(result.is_ok(), "re-burn should succeed: {:?}", result.err());

        let content = std::fs::read_to_string(&tmp_path).unwrap_or_else(|_| String::new());
        assert!(
            content.contains("[provenance=DerivedIssuer(1)]"),
            "derived-path burn audit must contain [provenance=DerivedIssuer(1)], got: {content:?}"
        );
        let _ = std::fs::remove_file(&tmp_path);
    }
}

/// SECURITY regression suite for the burn command (issue #41).
///
/// Pins the URL-placeholder safety guard: `cmd_burn` must refuse to burn a
/// template missing the `{picc}`/`{mac}` SDM placeholders (which would
/// produce an unverifiable, silently-bricked card) unless `--force` explicitly
/// opts out. The guard sits in `cmd_burn` (private to this binary crate) so it
/// is verified here rather than in the integration test binary.
#[cfg(test)]
mod security_tests {
    use super::cmd_burn;

    /// Acquire the global audit-log mutex and point the audit log at a fresh
    /// temp file. Every test that runs `cmd_burn` must call this first: the
    /// burn path writes to a process-global audit path, so without
    /// serialization a concurrent audit-content test would see stray lines.
    ///
    /// The `#[allow(clippy::await_holding_lock)]` on each async test covers
    /// holding the returned guard across `.await`.
    macro_rules! setup_audit_isolation {
        () => {{
            let _guard = crate::audit::AUDIT_TEST_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut path = std::env::temp_dir();
            path.push(format!(
                "bolty-security-burn-{}-{}.log",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let _ = std::fs::remove_file(&path);
            crate::audit::set_audit_log_path(path.clone());
            (_guard, path)
        }};
    }

    // SECURITY invariant: a URL lacking the {picc} placeholder must be rejected
    // before any card write occurs. Burning such a URL yields a card whose taps
    // carry no encrypted UID/counter — the server can never identify the card.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn url_without_picc_placeholder_is_rejected() {
        let (_guard, _path) = setup_audit_isolation!();
        let mut transport = crate::mock_transport::MockTransport::new();
        let keys_before = *transport.keys();
        let url = "https://example.com/?c={mac}";
        let err = cmd_burn(
            &mut transport,
            &[0u8; 16],
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await
        .expect_err("missing {picc} must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("must contain") && msg.contains("{picc}"),
            "error must explain the {{picc}} requirement, got: {msg}"
        );
        assert_eq!(
            transport.keys(),
            &keys_before,
            "no keys may change when the URL guard rejects the burn"
        );
    }

    // SECURITY invariant: a URL lacking the {mac} placeholder must be rejected.
    // Without {mac} the card never embeds a CMAC, so tap authenticity cannot be
    // verified — a silent integrity failure.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn url_without_mac_placeholder_is_rejected() {
        let (_guard, _path) = setup_audit_isolation!();
        let mut transport = crate::mock_transport::MockTransport::new();
        let keys_before = *transport.keys();
        let url = "https://example.com/?p={picc:uid+ctr}";
        let err = cmd_burn(
            &mut transport,
            &[0u8; 16],
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await
        .expect_err("missing {mac} must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("must contain") && msg.contains("{mac}"),
            "error must explain the {{mac}} requirement, got: {msg}"
        );
        assert_eq!(transport.keys(), &keys_before);
    }

    // SECURITY invariant: a URL with neither placeholder is rejected too (the
    // guard short-circuits on the first missing placeholder; this confirms the
    // `||` semantics, not an `&&` regression that would pass if one existed).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn url_with_no_placeholders_is_rejected() {
        let (_guard, _path) = setup_audit_isolation!();
        let mut transport = crate::mock_transport::MockTransport::new();
        let url = "https://example.com/static";
        let err = cmd_burn(
            &mut transport,
            &[0u8; 16],
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await
        .expect_err("placeholder-less URL must be rejected");
        assert!(
            format!("{err}").contains("must contain"),
            "error must mention the placeholder requirement"
        );
    }

    // SECURITY invariant: the guard must be bypassable with --force. This is
    // the documented escape hatch for advanced users who manage SDM externally.
    // If force stopped bypassing, legitimate power-user workflows would break.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn force_bypasses_url_guard() {
        let (_guard, path) = setup_audit_isolation!();
        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer = [0u8; 16];
        // No {picc}/{mac} but force=true: must NOT error on the URL guard.
        let result = cmd_burn(
            &mut transport,
            &issuer,
            "https://example.com/forced",
            1,
            false,
            false,
            None,
            true,
        )
        .await;
        let _ = std::fs::remove_file(&path);
        // The burn may still succeed (factory card). We only assert the URL
        // guard did not fire: the error (if any) must NOT mention placeholders.
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("must contain"),
                "force must bypass URL guard, but got: {msg}"
            );
        }
    }

    // SECURITY invariant: a correctly-formed URL passes the guard and reaches
    // the burn proper. This is the positive control for the negative tests
    // above and guards against an over-strict regression that rejects valid
    // templates.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn well_formed_url_passes_guard() {
        let (_guard, path) = setup_audit_isolation!();
        let mut transport = crate::mock_transport::MockTransport::new();
        let url = "https://card.bolt.local/?p={picc:uid+ctr}&c={mac}";
        let result = cmd_burn(
            &mut transport,
            &[0u8; 16],
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await;
        let _ = std::fs::remove_file(&path);
        assert!(
            result.is_ok(),
            "well-formed URL must pass the guard and burn, got: {:?}",
            result.err()
        );
    }

    // SECURITY invariant: the URL guard runs BEFORE any authentication or key
    // change. Concretely, a rejected burn must leave card keys untouched (the
    // negative assertions above already check this; this test restates the
    // invariant at the boundary by re-using the mock's untouched factory keys).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn url_guard_runs_before_card_modification() {
        let (_guard, _path) = setup_audit_isolation!();
        let mut transport = crate::mock_transport::MockTransport::new();
        let keys_before = *transport.keys();
        let ndef_before = transport.ndef().to_vec();
        let settings_before = transport.file_settings().to_vec();

        let _ = cmd_burn(
            &mut transport,
            &[0u8; 16],
            "https://example.com/no-placeholders",
            1,
            false,
            false,
            None,
            false,
        )
        .await;

        assert_eq!(transport.keys(), &keys_before, "keys must be untouched");
        assert_eq!(transport.ndef(), &ndef_before[..], "NDEF must be untouched");
        assert_eq!(
            transport.file_settings(),
            &settings_before[..],
            "file settings must be untouched"
        );
    }
}
