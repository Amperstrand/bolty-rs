use bolty_ntag::{AuthenticatedSession, File, Session, Transport};

use crate::common::gen_rnd_a;

/// f5-probe: interleaved GetFileSettings/ReadData/WriteData to verify
/// CmdCtr lockstep between host and card (the silicon-vs-applet A/B tool).
pub async fn cmd_f5probe<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default().get_selected_uid(transport).await?;
    println!("UID: {}", crate::to_hex(uid));

    let key = [0u8; 16];
    let mut s = Session::default()
        .authenticate_aes(transport, bolty_ntag::KeyNumber::Key0, &key, gen_rnd_a()?)
        .await?;
    println!("auth OK (factory zeros)");

    let mut f5a = 0u8;
    let mut ad = 0u8;
    let mut buf = [0u8; 8];
    for _ in 0..3u8 {
        let (_fs, s2) = s.get_file_settings(transport, File::Ndef).await?;
        f5a += 1;
        s = s2;
        match s.read_file_plain(transport, File::Ndef, 0, 4, &mut buf).await {
            Ok(_) => ad += 1,
            Err(e) => {
                println!("  read err: {e:?}");
                break;
            }
        }
    }
    let (mut _fs, s2) = s.get_file_settings(transport, File::Ndef).await?;
    let mut f5w = 1u8;
    s = s2;
    let payload = [0u8; 4];
    let mut wd = 0u8;
    match s.write_file_plain(transport, File::Ndef, 0, &payload).await {
        Ok(_) => wd += 1,
        Err(e) => println!("  write err: {e:?}"),
    }
    match s.get_file_settings(transport, File::Ndef).await {
        Ok(_) => f5w += 1,
        Err(e) => println!("  f5#2 err: {e:?}"),
    }
    println!("read-interleave:  F5 ok={f5a}/3, AD ok={ad}/3");
    println!("write-interleave: F5 ok={f5w}/2, 8D ok={wd}/1");
    Ok(())
}
