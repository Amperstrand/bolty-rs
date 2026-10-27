use anyhow::Context;
use bolty_ntag::{KeyNumber, Session, Transport};

use crate::common::gen_rnd_a;

/// Applet-specific (Play2BReal/ntag424-applet): SetCardUid INS 0x52 sets
/// the STORED uid that SDM embeds into p=. Plain APDU, requires an active
/// K0 session (README "personalize after auth"). Real NTAG424 has no such
/// command — do not use on silicon.
pub async fn cmd_set_card_uid<T: Transport>(transport: &mut T, uid_hex: &str) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = crate::decode_hex::<7>(uid_hex.trim())
        .map_err(|e| anyhow::anyhow!("uid: {e}"))?;

    let session = Session::default();
    let card_uid = session.get_selected_uid(transport).await?;
    println!("Card UID (RF): {}", crate::to_hex(card_uid));

    let _s = session
        .authenticate_aes(transport, KeyNumber::Key0, &[0u8; 16], gen_rnd_a()?)
        .await
        .context("factory K0 auth failed (card must be BLANK for this helper)")?;
    println!("authenticated with factory K0");

    let mut apdu = [0x90u8, 0x52, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0];
    apdu[5..12].copy_from_slice(&uid);
    let resp = transport.transmit(&apdu).await.context("transmit 0x52")?;
    anyhow::ensure!(
        resp.sw1 == 0x91 && resp.sw2 == 0x00,
        "SetCardUid failed: SW={:02X}{:02X}",
        resp.sw1,
        resp.sw2
    );
    println!("stored UID set to {} — SDM p= will now embed it", uid_hex);
    Ok(())
}
