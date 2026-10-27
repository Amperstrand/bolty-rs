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
    let mut f5w = 0u8;
    let mut wd = 0u8;
    let mut buf = [0u8; 8];
    let payload = [0u8; 4];
    'probe: {
        for _ in 0..3u8 {
            match s.get_file_settings(transport, File::Ndef).await {
                Ok((_fs, s2)) => {
                    f5a += 1;
                    s = s2;
                }
                Err(e) => {
                    println!("  F5 err (read loop, after {f5a} ok): {e:?}");
                    break 'probe;
                }
            }
            match s
                .read_file_plain(transport, File::Ndef, 0, 4, &mut buf)
                .await
            {
                Ok(_) => ad += 1,
                Err(e) => {
                    println!("  read err (read loop, after {ad} ok): {e:?}");
                    break 'probe;
                }
            }
        }
        match s.get_file_settings(transport, File::Ndef).await {
            Ok((_fs, s2)) => {
                f5w += 1;
                s = s2;
            }
            Err(e) => {
                println!("  F5 err (pre-write): {e:?}");
                break 'probe;
            }
        }
        match s.write_file_plain(transport, File::Ndef, 0, &payload).await {
            Ok(_) => wd += 1,
            Err(e) => {
                println!("  write err: {e:?}");
                break 'probe;
            }
        }
        match s.get_file_settings(transport, File::Ndef).await {
            Ok((_fs, _s2)) => f5w += 1,
            Err(e) => println!("  f5#2 err: {e:?}"),
        }
    }
    println!("read-interleave:  F5 ok={f5a}/3, AD ok={ad}/3");
    println!("write-interleave: F5 ok={f5w}/2, 8D ok={wd}/1");
    if f5a == 3 && ad == 3 && f5w == 2 && wd == 1 {
        return Ok(());
    }
    // Emulator footgun (2026-10-27 lane finding): without the compat flag
    // the FIRST F5/AD pair succeeds and everything after fails — looking
    // exactly like the desync race this probe exists to catch.
    if std::env::var_os("BOLTY_EMU_COUNTER_COMPAT").is_none() {
        println!(
            "hint: NTAG424-emulation applets (J3R180 etc.) need \
             BOLTY_EMU_COUNTER_COMPAT=1 — plain reads advance CmdCtr there; \
             rerun with it set before concluding a transport fault"
        );
    }
    // not fully clean: make it machine-detectable (soak loops / CI key on
    // the exit code, the counters stay in stdout for humans)
    std::process::exit(1);
}
