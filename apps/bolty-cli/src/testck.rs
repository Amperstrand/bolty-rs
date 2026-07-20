use anyhow::Context;
use bolty_core::provenance::KeyProvenance;
use bolty_ntag::{AuthenticatedSession, KeyNumber, NonMasterKeyNumber, Session, Transport};

use crate::audit;
use crate::common::gen_rnd_a;

const TEST_KEY: [u8; 16] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF,
];

pub async fn cmd_testck<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    println!("Card UID: {}", crate::to_hex(uid));
    println!("\n[testck] ChangeKey A/B test — round-trip on key 1");
    audit::log_event_with_provenance("testck: starting", Some(KeyProvenance::StaticTestKey));

    let rnd_a = gen_rnd_a()?;
    let session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &[0u8; 16], rnd_a)
        .await
        .context("factory K0 auth failed — card not blank or in auth delay")?;
    println!("[testck] Auth K0 (zeros): OK");

    let (kv_before, session) = session.get_key_version(transport, KeyNumber::Key1).await?;
    println!("[testck] Key 1 version before: 0x{kv_before:02X}");

    if kv_before != 0 {
        anyhow::bail!("[testck] Key 1 not at factory (0x00) — use on blank cards only");
    }

    println!("[testck] Step 1: ChangeKey(1, zero→test, ver=0x01)");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key1,
            &TEST_KEY,
            1,
            &[0u8; 16],
        )
        .await
        .context("ChangeKey step 1 failed")?;
    println!("[testck]   Result: OK");

    let (kv_mid, session) = session.get_key_version(transport, KeyNumber::Key1).await?;
    println!("[testck]   Key 1 version: 0x{kv_mid:02X}");
    if kv_mid != 1 {
        anyhow::bail!("[testck] Step 1 FAIL — key version not 0x01");
    }
    println!("[testck]   Step 1: PASS");

    println!("[testck] Step 2: ChangeKey(1, test→zero, ver=0x00)");
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key1,
            &[0u8; 16],
            0,
            &TEST_KEY,
        )
        .await
        .context("ChangeKey step 2 failed")?;
    println!("[testck]   Result: OK");

    let (kv_final, _) = session.get_key_version(transport, KeyNumber::Key1).await?;
    println!("[testck]   Key 1 version: 0x{kv_final:02X}");
    if kv_final != 0 {
        anyhow::bail!("[testck] Step 2 FAIL — key version not 0x00");
    }
    println!("[testck]   Step 2: PASS");

    println!("\n✅ testck: ALL PASS — ChangeKey verified");
    audit::log_event_with_provenance("testck: ALL PASS", Some(KeyProvenance::StaticTestKey));
    Ok(())
}
