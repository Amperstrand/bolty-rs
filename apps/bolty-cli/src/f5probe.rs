use bolty_ntag::Transport;

use crate::common::gen_rnd_a;

/// f5-probe: interleaved GetFileSettings/ReadData/WriteData to verify
/// CmdCtr lockstep between host and card (the silicon-vs-applet A/B tool).
/// Counter semantics live in bolty_ntag::f5probe; this wrapper keeps the
/// run self-diagnosing (hint + machine-readable exit code).
pub async fn cmd_f5probe<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let r = bolty_ntag::f5probe(transport, gen_rnd_a()?)
        .await
        .map_err(|e| anyhow::anyhow!("f5probe: {e:?}"))?;
    let ((f5a, ad), (f5w, wd)) = r;
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
