use anyhow::Context;
use bolty_core::constants::FACTORY_KEY;
use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use bolty_ntag::{Session, Transport};

use crate::common::{gen_rnd_a, uid_to_fixed};

pub async fn cmd_keyver<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
    version: u8,
    json_mode: bool,
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_fixed = uid_to_fixed(&uid);
    let uid_hex = crate::to_hex(uid_fixed);

    if !json_mode {
        println!("Card UID: {uid_hex}");
    }

    let keys = BoltcardDeterministicDeriver::derive_keys(
        issuer_key,
        CardUid::new(uid_fixed),
        version as u32,
    );
    let derived_k0 = keys.k0.as_bytes();

    let rnd_a = gen_rnd_a()?;
    let (versions, k0_label) =
        match bolty_ntag::check_key_versions(transport, derived_k0, rnd_a).await {
            Ok(v) => (v, format!("derived K0 (version {version})")),
            Err(_) => {
                let rnd_a = gen_rnd_a()?;
                let v = bolty_ntag::check_key_versions(transport, &FACTORY_KEY, rnd_a)
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
