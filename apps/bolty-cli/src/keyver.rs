use ntag424::Transport;

use crate::common::gen_rnd_a;

pub async fn cmd_keyver<T: Transport>(
    transport: &mut T,
    issuer_key: &[u8; 16],
) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let rnd_a = gen_rnd_a()?;
    let versions = bolty_ntag::check_key_versions(transport, issuer_key, rnd_a)
        .await
        .map_err(|e| {
            anyhow::anyhow!("failed to read key versions (wrong key or auth-delay?): {e:?}")
        })?;

    let factory_ver = bolty_ntag::FACTORY_KEY_VERSION;

    println!("Key versions (authenticated via K0):");
    let labels = ["K0 (master)", "K1 (SDM PICC)", "K2 (SDM MAC)", "K3", "K4"];
    for (label, v) in labels.iter().zip(versions.iter()) {
        println!("  {label}: 0x{v:02X}");
    }

    let all_factory = versions.iter().all(|&v| v == factory_ver);
    if all_factory {
        println!("\nAll keys at factory version (0x{factory_ver:02X}) — card is BLANK.");
    } else if versions[1] != factory_ver && versions[2] != factory_ver {
        println!("\nK1/K2 have non-factory versions — card appears PROVISIONED.");
    }

    Ok(())
}
