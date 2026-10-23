//! Read-only card auth-budget accounting (hermes card t_0289945f, revised).
//!
//! AN12196 §7.4 counter economics: 50 consecutive failures start the auth
//! delay (SeqFailCtr); **1000 TOTAL failures permanently lock the key**
//! (TotFailCtr — ChangeKey is the only reset). Recovery work spends this
//! budget (2026-10-19 card recovery).
//!
//! **Why host-side accounting, not a card readout** (live-established
//! 2026-10-23 on card 04c474fa967380): NTAG424 exposes the failure
//! counters through NO plain command. INS 0x64 — which DESFire lore calls
//! GetKeySettings — is **GetKeyVersion** on NT4H2421Gx (§10.6.2,
//! CommMode.MAC: requires an authenticated secure channel; sent raw it
//! answers `91 7E` PermissionDenied, before AND after authentication).
//! The fork's `get_key_version` implements the real MAC-secured path and
//! `keyver` reads key versions that way; the failure counters are
//! internal per AN12196 and simply are not wire-readable. Hence: count
//! what WE spent — every `91 AE` the audit log recorded against this host
//! since the last `wipe: SUCCESS` (which resets the card's counters via
//! ChangeKey, restarting the budget epoch).
//!
//! Honest limits, printed with every report: the audit log is host-local
//! and boot-scoped (/tmp), counts only bolty-cli-attempted
//! authentications, and 91 AD delay responses are excluded (the card does
//! not evaluate the key during delay, so they do not spend TotFailCtr).

use std::path::PathBuf;

use anyhow::Context;

const DEFAULT_LOG: &str = "/tmp/bolty-audit.log";

pub struct BudgetReport {
    pub auth_failures: u64,
    pub delay_events: u64,
    pub wipes: u64,
    pub log_lines: u64,
    pub since_last_wipe: Option<u64>,
}

/// Parse an audit log and account auth-failure spend.
///
/// Counting rules:
/// - `RX ... sw=91ae` — one TotFailCtr spend (failed key evaluation)
/// - `RX ... sw=91ad` — delay response; tracked as info, spends nothing
/// - `EVENT  wipe: SUCCESS` — budget epoch reset (ChangeKey resets the
///   card's counters); failures before it do not carry over
pub fn parse_audit(text: &str) -> BudgetReport {
    let mut report = BudgetReport {
        auth_failures: 0,
        delay_events: 0,
        wipes: 0,
        log_lines: 0,
        since_last_wipe: None,
    };
    let mut failures_since_wipe: u64 = 0;
    let mut seen_wipe = false;
    for line in text.lines() {
        report.log_lines += 1;
        let lower = line.to_ascii_lowercase();
        if lower.contains("rx") && lower.contains("sw=91ae") {
            report.auth_failures += 1;
            failures_since_wipe += 1;
        } else if lower.contains("rx") && lower.contains("sw=91ad") {
            report.delay_events += 1;
        } else if lower.contains("wipe: success") {
            report.wipes += 1;
            seen_wipe = true;
            failures_since_wipe = 0;
        }
    }
    report.since_last_wipe = seen_wipe.then_some(failures_since_wipe);
    report
}

pub fn cmd_budget(log: Option<PathBuf>, json_mode: bool) -> anyhow::Result<()> {
    let path = log.unwrap_or_else(|| PathBuf::from(DEFAULT_LOG));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read audit log at {}", path.display()))?;
    let r = parse_audit(&text);
    crate::audit::log_event("budget: host-side accounting report");

    let effective = r.since_last_wipe.unwrap_or(r.auth_failures);
    if json_mode {
        println!(
            r#"{{"ok":true,"log":"{}","lines":{},"auth_failures_total":{},"auth_failures_since_last_wipe":{},"delay_events":{},"wipes":{},"budget_ceiling":1000}}"#,
            path.display(),
            r.log_lines,
            r.auth_failures,
            effective,
            r.delay_events,
            r.wipes,
        );
        return Ok(());
    }

    println!("Auth-budget accounting from {}", path.display());
    println!("  Failed key evaluations (91 AE): {}", r.auth_failures);
    match r.since_last_wipe {
        Some(since) => println!(
            "  Since last wipe:SUCCESS epoch:  {since}  (budget {}/1000)",
            1000u64.saturating_sub(since)
        ),
        None => println!(
            "  Since last wipe:SUCCESS epoch:  {}  (budget {}/1000) [no wipe in log — total]",
            r.auth_failures,
            1000u64.saturating_sub(r.auth_failures)
        ),
    }
    println!(
        "  Delay responses (91 AD, spend nothing): {}",
        r.delay_events
    );
    println!("  Wipe epochs (ChangeKey resets counters): {}", r.wipes);
    if effective >= 900 {
        println!("⚠️  estimated near permanent lock — STOP authenticating this card");
    }
    println!(
        "\nLimits: host-local, boot-scoped log, bolty-cli attempts only; the\n\
         card's internal counters are NOT wire-readable on NTAG424 (INS 0x64 is\n\
         GetKeyVersion, MAC-secured; live-established 2026-10-23)."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_audit;

    #[test]
    fn counts_failures_delays_and_wipe_epochs() {
        let text = "\
[1] TX APDU len=8 data=9071000005000300000000
[1] RX OK   sw=91ae len=2 data=91AE
[2] RX OK   sw=91ad len=2 data=91AD
[3] EVENT  wipe: SUCCESS — all keys reset to factory zeros [provenance=DerivedIssuer(1)]
[4] TX APDU len=8 data=9071000005000300000000
[4] RX OK   sw=91ae len=2 data=91AE
[5] EVENT  try-key: ACCEPTED K0 [provenance=UnknownExternal]
";
        let r = parse_audit(text);
        assert_eq!(r.auth_failures, 2);
        assert_eq!(r.delay_events, 1);
        assert_eq!(r.wipes, 1);
        assert_eq!(r.since_last_wipe, Some(1));
        assert_eq!(r.log_lines, 7);
    }

    #[test]
    fn no_wipe_means_total_epoch() {
        let text = "[1] RX OK   sw=91ae len=2 data=91AE\n";
        let r = parse_audit(text);
        assert_eq!(r.since_last_wipe, None);
        assert_eq!(r.auth_failures, 1);
    }

    #[test]
    fn non_auth_91ae_lines_are_not_counted() {
        let text = "[1] TX APDU len=4 data=9064000000\n[1] RX OK sw=917e\n";
        let r = parse_audit(text);
        assert_eq!(r.auth_failures, 0);
    }

    #[test]
    fn empty_log_is_zero_everything() {
        let r = parse_audit("");
        assert_eq!(r.auth_failures, 0);
        assert_eq!(r.since_last_wipe, None);
        assert_eq!(r.log_lines, 0);
    }
}
