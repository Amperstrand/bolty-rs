use anyhow::Context;
use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::provenance::KeyProvenance;
use bolty_core::secret::{AesKey, CardKeys};
use bolty_core::uid::CardUid;
use bolty_ntag::{AuthenticatedSession, File, KeyNumber, Session, Transport};

use crate::audit;
use crate::common::{
    AuthRetry, gen_rnd_a, is_auth_delay, is_sdm_functionally_active, map_ntag_error,
    record_auth_failure,
};

pub async fn cmd_wipe<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    version: u8,
    verbose: bool,
    dry_run: bool,
    confirm_uid: Option<&[u8; 7]>,
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
                "UID mismatch: expected {}, got {} — refusing to wipe wrong card",
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
        println!("Derived K0: {}", crate::to_hex(keys.k0.as_bytes()));
    }

    if dry_run {
        println!("\n=== DRY RUN — no card modifications ===");
        println!("Version:   {version}");
        println!("\nPlanned steps:");
        println!("  [1] Authenticate (factory K0 or derived K0)");
        println!("  [2] Clear SDM file settings");
        println!("  [3] Write empty NDEF (NLEN=0)");
        println!("  [4] Reset K1 to factory");
        println!("  [5] Reset K2 to factory");
        println!("  [6] Reset K3 to factory");
        println!("  [7] Reset K4 to factory, then K0 (master)");
        println!("  Post:  Re-authenticate with factory K0 + verify");
        println!("\nNo APDUs sent. Card unchanged.");
        return Ok(());
    }

    println!("[0/7] Checking card state...");
    let factory_probe = {
        let rnd_a = gen_rnd_a()?;
        Session::default()
            .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
            .await
            .is_ok()
    };

    if factory_probe {
        anyhow::bail!(
            "card has factory K0 — already BLANK or half-wiped.\n\
             Use 'burn' to provision, or diagnose for details."
        );
    }
    println!("  Card is PROVISIONED (factory K0 rejected). Proceeding with wipe.");

    // Factory K0 probe: detect already-wiped cards (single attempt, no retry).
    // If factory K0 works and the card is clean, return early.
    // If factory K0 works but card has residual state, bail with instructions.
    let rnd_a = gen_rnd_a()?;
    if let Ok(session) = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await
    {
        let (settings, mut session) = session
            .get_file_settings(transport, File::Ndef)
            .await
            .context("failed to read file settings with factory K0")?;

        let has_sdm = is_sdm_functionally_active(settings.sdm.as_ref());
        let mut buf = [0u8; 256];
        let len = session
            .read_file_plain(transport, File::Ndef, 0, 0, &mut buf)
            .await
            .context("failed to read NDEF with factory K0")?;
        #[allow(clippy::indexing_slicing)]
        let has_ndef = len >= 2 && (buf[0] != 0x00 || buf[1] != 0x00);

        if !has_sdm && !has_ndef {
            println!("Card already wiped (factory keys, no SDM, empty NDEF). Nothing to do.");
            return Ok(());
        }
        anyhow::bail!(
            "Factory K0 works but card has residual state (SDM={}, NDEF={} bytes).\n\
             Card may have been partially wiped. Use `burn` to re-burn first, then `wipe`.",
            has_sdm,
            if has_ndef { len } else { 0 }
        );
    }

    // BOLT_DET: 1. Read the NDEF lnurlw URL, extract `p=` and `c=`.
    // 2. Derive `Encryption Key (K1)`, decrypt `p=` to obtain the `PICCData`.
    // 3. Check `PICCData[0] == 0xc7`.

    // BOLT_DET: 9. Verify that the SUN MAC in `c=` matches the one calculated using `Authentication Key (K2)`.

    // BOLT_DET: Rational: Attempting to call `AuthenticateEV2First` without validating the `p=` and `c=` parameters could render the NTag inoperable after a few attempts.

    // DET:57-59 pre-verification (bolty-rs#72, first conformant implementation
    // in the ecosystem per the cross-implementation audit): validate the p/c
    // the card is actually mirroring BEFORE the first AuthenticateEV2First.
    // Non-hex p/c values (template placeholders — SDM not mirroring on this
    // interface) skip the gate; hex values that fail decryption or the SUN
    // MAC refuse the wipe (wrong issuer key / version — the DET:72 brick guard).
    println!("Pre-verifying p/c (DET:57-59)...");
    pre_verify_pc(transport, &keys, &uid_fixed).await?;

    // Derived K0 auth with AuthRetry (handles auth delay backoff).
    // The library re-authenticates internally, but we probe first to get
    // past any auth delay and give a clear error message on failure.
    println!("Authenticating with derived K0...");
    {
        let mut retry = AuthRetry::new();
        let result = loop {
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
        if !result {
            anyhow::bail!("derived K0 authentication failed — wrong issuer key or card not burned");
        }
    }

    // Delegate to library: it handles SDM disable, NDEF clear, key reset, verification.
    let keyset = CardKeys {
        k0: keys.k0.clone(),
        k1: keys.k1.clone(),
        k2: keys.k2.clone(),
        k3: keys.k3.clone(),
        k4: keys.k4.clone(),
    };

    let rnd_a = AesKey::new(gen_rnd_a()?);
    let provenance = KeyProvenance::DerivedIssuer { version };
    println!("\nWiping card...");
    audit::log_event_with_provenance(
        &format!(
            "wipe: starting — UID={}, version={version}",
            crate::to_hex(uid_fixed)
        ),
        Some(provenance),
    );
    if let Err(e) = bolty_ntag::wipe(transport, &keyset, rnd_a).await {
        audit::log_event_with_provenance("wipe: FAILED", Some(provenance));
        return Err(map_ntag_error(e));
    }

    audit::log_event_with_provenance(
        "wipe: SUCCESS — all keys reset to factory zeros",
        Some(provenance),
    );
    println!("\n✅ Card wiped and verified successfully!");
    Ok(())
}

/// DET:57-59 pre-wipe gate: read the NDEF URL unauthenticated (read=Free on
/// provisioned cards), extract p=/c=, decrypt `p` with the derived K1 and
/// verify the SUN MAC in `c` with the derived K2 — all before the first
/// AuthenticateEV2First. Refusal protects against wiping with a wrong issuer
/// key/version (the DET:72 inoperable-tag risk).
async fn pre_verify_pc<T: Transport>(
    transport: &mut T,
    keys: &bolty_core::derivation::CardKeySet,
    uid_fixed: &[u8; 7],
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    use bolty_core::picc::{extract_p_and_c, picc_decrypt_p, picc_verify_c};

    let mut buf = [0u8; 256];
    let len = Session::default()
        .read_file_unauthenticated(transport, File::Ndef, 0, &mut buf)
        .await
        .context("pre-verification: failed to read NDEF")?;
    let data = buf.get(..len.min(buf.len())).unwrap_or(&[]);
    let parsed = crate::common::parse_ndef_uri(data)
        .context("pre-verification: NDEF unreadable — refusing blind wipe")?;

    let Some((p_hex, c_hex)) = extract_p_and_c(&parsed.url) else {
        println!("  no p/c in NDEF — skipping pre-verification (non-SDM URL)");
        return Ok(());
    };

    let is_hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    let is_zero_hex = |s: &str| s.bytes().all(|b| b == b'0');
    if !is_hex(p_hex) || !is_hex(c_hex) {
        println!("  p/c are template placeholders — skipping pre-verification");
        return Ok(());
    }
    if is_zero_hex(p_hex) || is_zero_hex(c_hex) {
        println!("  p/c are static zeros (SDM not mirroring on this read) — skipping");
        return Ok(());
    }

    let picc = picc_decrypt_p(keys.k1.as_bytes(), p_hex)
        .context("pre-verification: p= decryption failed — wrong issuer key or version")?;
    anyhow::ensure!(
        picc.uid.as_ref() == Some(uid_fixed),
        "pre-verification: p= UID {} does not match card UID {} — refusing",
        picc.uid
            .as_ref()
            .map(crate::to_hex)
            .unwrap_or_else(|| "none (privacy mode)".to_string()),
        crate::to_hex(uid_fixed),
    );
    anyhow::ensure!(
        picc_verify_c(keys.k2.as_bytes(), &picc, c_hex),
        "pre-verification: SUN MAC mismatch — wrong issuer key or version, refusing to wipe",
    );
    println!("  ✓ p/c verified (UID + counter + SUN MAC valid)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolty_core::crypto::aes_cmac;
    use bolty_core::picc::{PiccData, sdm_build_sv2};

    fn encrypt_p_hex(key: &[u8; 16], picc: &PiccData) -> String {
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let mut plaintext = [0u8; 16];
        plaintext[0] = 0xC7;
        if let Some(uid) = &picc.uid {
            plaintext[1..8].copy_from_slice(uid);
        }
        plaintext[8] = picc.counter as u8;
        plaintext[9] = (picc.counter >> 8) as u8;
        plaintext[10] = (picc.counter >> 16) as u8;
        let pt_len = plaintext.len();
        let ct = Aes128CbcEnc::new(key.into(), (&[0u8; 16]).into())
            .encrypt_padded::<NoPadding>(&mut plaintext, pt_len)
            .expect("in-length block");
        crate::to_hex(ct).to_lowercase()
    }

    fn sun_mac_hex(k2: &[u8; 16], uid: &[u8; 7], counter: u32) -> String {
        let sv2 = sdm_build_sv2(uid, counter);
        let ks = aes_cmac(k2, &sv2);
        let full = aes_cmac(&ks, &[]);
        let odd: Vec<u8> = (0..8).map(|i| full[i * 2 + 1]).collect();
        crate::to_hex(odd).to_lowercase()
    }

    fn ndef_file_with_url(url: &str) -> Vec<u8> {
        let payload_len = url.len() + 1;
        let record_len = 4 + payload_len;
        let mut file = Vec::with_capacity(2 + record_len);
        file.push((record_len >> 8) as u8);
        file.push(record_len as u8);
        file.push(0xD1);
        file.push(0x01);
        file.push(payload_len as u8);
        file.push(b'U');
        file.push(0x00);
        file.extend_from_slice(url.as_bytes());
        file
    }

    async fn provisioned_with_sdm_p_c(
        issuer_key: &[u8; 16],
        c_hex: &str,
    ) -> crate::mock_transport::MockTransport {
        let mut transport = crate::mock_transport::MockTransport::new();
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        crate::burn::cmd_burn(
            &mut transport,
            issuer_key,
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await
        .expect("burn to provision card");

        let keys = BoltcardDeterministicDeriver::derive_keys(
            issuer_key,
            CardUid::new(crate::mock_transport::UID),
            1,
        );

        let picc = PiccData {
            valid: false,
            uid: Some(crate::mock_transport::UID),
            counter: 42,
            has_counter: true,
        };
        let p_hex = encrypt_p_hex(keys.k1.as_bytes(), &picc);
        let url_with_hex = format!("https://card.bolt.local/lnurl?p={p_hex}&c={c_hex}");
        transport.replace_ndef(ndef_file_with_url(&url_with_hex));
        transport
    }

    #[tokio::test]
    async fn wipe_refuses_when_sdm_mac_mismatches() {
        let issuer_key = [0x42u8; 16];
        let mut transport = provisioned_with_sdm_p_c(&issuer_key, "deadbeefdeadbeef").await;

        let result = cmd_wipe(&mut transport, &issuer_key, 1, false, false, None).await;
        let err = result.expect_err("wipe must refuse on SUN MAC mismatch");
        assert!(
            err.to_string().contains("SUN MAC"),
            "error must name the SUN MAC failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn wipe_proceeds_when_sdm_pc_valid() {
        let issuer_key = [0x42u8; 16];
        let mut transport = crate::mock_transport::MockTransport::new();
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        crate::burn::cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await
        .expect("burn to provision card");

        let keys = BoltcardDeterministicDeriver::derive_keys(
            &issuer_key,
            CardUid::new(crate::mock_transport::UID),
            1,
        );
        let picc = PiccData {
            valid: false,
            uid: Some(crate::mock_transport::UID),
            counter: 42,
            has_counter: true,
        };
        let p_hex = encrypt_p_hex(keys.k1.as_bytes(), &picc);
        let c_hex = sun_mac_hex(keys.k2.as_bytes(), &crate::mock_transport::UID, 42);
        let url_with_hex = format!("https://card.bolt.local/lnurl?p={p_hex}&c={c_hex}");
        transport.replace_ndef(ndef_file_with_url(&url_with_hex));

        let result = cmd_wipe(&mut transport, &issuer_key, 1, false, false, None).await;
        assert!(
            result.is_ok(),
            "wipe with valid p/c must succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn dry_run_preserves_provisioned_card_state() {
        let mut transport = crate::mock_transport::MockTransport::new();

        let issuer_key = [0u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";

        crate::burn::cmd_burn(
            &mut transport,
            &issuer_key,
            url,
            1,
            false,
            false,
            None,
            false,
        )
        .await
        .expect("burn to provision card for wipe dry-run test");

        let keys_before = *transport.keys();
        let ndef_before = transport.ndef().to_vec();
        let settings_before = transport.file_settings().to_vec();

        let result = cmd_wipe(&mut transport, &issuer_key, 1, false, true, None).await;
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
    async fn wipe_logs_derived_provenance() {
        let _guard = crate::audit::AUDIT_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut tmp_path = std::env::temp_dir();
        tmp_path.push(format!("bolty-audit-wipe-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&tmp_path);
        crate::audit::set_audit_log_path(tmp_path.clone());

        let mut transport = crate::mock_transport::MockTransport::new();
        let issuer_key = [0x42u8; 16];
        let url = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c={mac}";
        let _ = crate::burn::cmd_burn(
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
        let _ = std::fs::remove_file(&tmp_path);
        let _ = cmd_wipe(&mut transport, &issuer_key, 1, false, false, None).await;

        let content = std::fs::read_to_string(&tmp_path).unwrap_or_default();
        assert!(
            content.contains("[provenance=DerivedIssuer(1)]"),
            "wipe audit must contain [provenance=DerivedIssuer(1)], got: {content:?}"
        );
        let _ = std::fs::remove_file(&tmp_path);
        crate::audit::reset_audit_log_path_for_test();
    }
}
