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
             (verify-before-mutation. NOTE: a wipe clears keys/SDM but NOT the\n\
             NDEF payload — post-wipe cards still gate; use --force for a\n\
             read-only probe, or a factory-fresh card for the full write leg)"
        ),
        Err(e) => return Err(anyhow::anyhow!("f5probe: {e:?}")),
    };
    println!(
        "read-interleave:  F5 ok={}/3, AD ok={}/3",
        r.read_f5, r.read_ad
    );
    if r.write_skipped {
        // deliberate, not a failure: with SDM mirroring the ReadData view
        // is PROCESSED data, not the raw template — an 8D write-back would
        // corrupt the template (hardware-observed on the J3R180, NLEN
        // zeroed). Forced runs on a non-blank card are read-only.
        println!(
            "write-interleave: SKIPPED (NDEF holds data — the write-back\n\
             would corrupt the raw template through the SDM-mirrored read view)"
        );
        if r.read_f5 == 3 && r.read_ad == 3 {
            return Ok(());
        }
        std::process::exit(1);
    }
    println!(
        "write-interleave: F5 ok={}/2, 8D ok={}/1",
        r.write_f5, r.write_8d
    );
    if r.read_f5 == 3 && r.read_ad == 3 && r.write_f5 == 2 && r.write_8d == 1 {
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
