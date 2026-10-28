use bolty_ntag::Transport;

use crate::common::gen_rnd_a;

/// f5-probe: interleaved GetFileSettings/ReadData/WriteData to verify
/// CmdCtr lockstep between host and card (the silicon-vs-applet A/B tool).
/// Counter semantics live in bolty_ntag::f5probe; this wrapper keeps the
/// run self-diagnosing (hint + machine-readable exit code) and maps the
/// #233 non-blank-NDEF gate to an actionable message.
pub async fn cmd_f5probe<T: Transport>(transport: &mut T, force: bool) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let r = match bolty_ntag::f5probe(transport, gen_rnd_a()?, force).await {
        Ok(r) => r,
        Err(bolty_ntag::Error::NdefNotEmpty { len }) => anyhow::bail!(
            "NDEF holds {len} bytes of data — refusing to probe without --force\n\
             (the write leg preserves content, but verify-before-mutation wins; \
             burn/wipe the card first if this is lab stock)"
        ),
        Err(e) => return Err(anyhow::anyhow!("f5probe: {e:?}")),
    };
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
