use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::secret::AesKey;
use bolty_core::uid::CardUid;
use bolty_ntag::Transport;

use crate::common::gen_rnd_a;
use crate::uid::{UidFallback, uid_or_fallback};

pub async fn cmd_keyver<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    version: u8,
    json_mode: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    // UID: EnvOrBail — keyver needs the actual UID for derivation; the
    // BOLTY_UID_FALLBACK env supplies it for broker transports.
    let uid_hex_owned = uid_or_fallback(transport, UidFallback::EnvOrBail).await?;
    let uid_fixed: [u8; 7] = {
        let mut out = [0u8; 7];
        let bytes = uid_hex_owned.as_bytes();
        let pairs: Vec<&[u8]> = (0..7).filter_map(|i| bytes.get(i * 2..i * 2 + 2)).collect();
        for (slot, pair) in out.iter_mut().zip(pairs) {
            let hex_pair =
                std::str::from_utf8(pair).map_err(|_| anyhow::anyhow!("bad fallback hex"))?;
            *slot = u8::from_str_radix(hex_pair, 16)
                .map_err(|_| anyhow::anyhow!("bad fallback hex"))?;
        }
        out
    };
    let uid_hex = crate::to_hex(uid_fixed);

    if !json_mode {
        println!("Card UID: {uid_hex}");
    }

    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        version as u32,
    );
    let derived_k0 = &keys.k0;

    let rnd_a = gen_rnd_a()?;
    let (versions, k0_label) =
        match bolty_ntag::check_key_versions(transport, derived_k0, AesKey::new(rnd_a)).await {
            Ok(v) => (v, format!("derived K0 (version {version})")),
            Err(_) => {
                let rnd_a = gen_rnd_a()?;
                let v = bolty_ntag::check_key_versions(
                    transport,
                    &AesKey::new(FACTORY_KEY),
                    AesKey::new(rnd_a),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "authentication failed with both derived K0 and factory K0: {e:?}"
                    )
                })?;
                (v, "factory K0".to_string())
            }
        };

    if json_mode {
        println!(
            r#"{{"ok":true,"uid":"{uid_hex}","versions":[{},{},{},{},{}],"authenticated_via":"{k0_label}"}}"#,
            versions[0], versions[1], versions[2], versions[3], versions[4]
        );
    } else {
        println!("\nKey versions (authenticated via {k0_label}):");
        let labels = ["K0 (master)", "K1 (SDM PICC)", "K2 (SDM MAC)", "K3", "K4"];
        for (label, v) in labels.iter().zip(versions.iter()) {
            println!("  {label}: 0x{v:02X}");
        }

        let all_factory = versions.iter().all(|&v| v == 0);
        if all_factory {
            println!("\nAll keys at factory version (0x00) — card is BLANK.");
        } else if versions[1] != 0 && versions[2] != 0 {
            println!("\nK1/K2 have non-factory versions — card appears PROVISIONED.");
        }
    }

    Ok(())
}
