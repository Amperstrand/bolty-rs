//! Read-only card auth-budget probe (hermes card t_0289945f).
//!
//! AN12196 §7.4 counter economics: 50 consecutive failures start the auth
//! delay (SeqFailCtr, cleared by keep-trying / successful auth /
//! ChangeKey); **1000 TOTAL failures permanently lock the key**
//! (TotFailCtr, cleared ONLY by ChangeKey). Recovery work spends this
//! budget (2026-10-19: the recovered card 043365fa967380) and until now
//! it was tracked in prose.
//!
//! GetKeySettings (INS 64h) is an unauthenticated read — the 2026-08
//! session ran it against a card nobody could authenticate.
//!
//! Layout provenance: the DESFire-family prefix (KeySettings(1) ||
//! NumKeys(1) || KeyVersion[NumKeys]) is firm. The counter trailer
//! (SeqFailCtr(1) || TotFailCtr(2 LE) || SpentTimeCtr(2 LE)) is the
//! documented shape but has not been live-verified against a real card
//! (2026-10-21: the readers carry J3R180 cards from another project).
//! Output therefore ALWAYS includes the raw response hex; the structured
//! parse is best-effort and labeled.

use anyhow::Context;
use bolty_ntag::{Session, Transport};

const GET_KEY_SETTINGS: &[u8] = &[0x90, 0x64, 0x00, 0x00, 0x00];

pub struct Budget {
    pub key_settings: u8,
    pub num_keys: u8,
    pub key_versions: Vec<u8>,
    /// False when NumKeys is out of the sane range (<= 0x0F) — the
    /// response shape then does not match the DESFire core and every
    /// structured field is untrusted (2026-08 capture behaves this way:
    /// NumKeys byte 0x40 => 19 bytes cannot be versions; that dump was
    /// likely not a raw GetKeySettings body).
    pub core_trusted: bool,
    pub seq_fail_ctr: Option<u16>,
    pub tot_fail_ctr: Option<u16>,
    pub spent_time_ctr: Option<u16>,
    pub raw: Vec<u8>,
}

/// Parse a GetKeySettings response body (status word already stripped).
///
/// Tolerates unknown trailing data: the core prefix is parsed firmly,
/// the counter trailer only when at least 5 bytes remain after the key
/// versions, and nothing is guessed beyond that — `raw` carries the truth.
pub fn parse_budget(body: &[u8]) -> Option<Budget> {
    if body.len() < 2 {
        return None;
    }
    let key_settings = *body.first()?;
    let num_keys = *body.get(1)?;
    if num_keys > 0x0F {
        // Core does not fit the DESFire shape — keep raw only.
        return Some(Budget {
            key_settings,
            num_keys,
            key_versions: Vec::new(),
            core_trusted: false,
            seq_fail_ctr: None,
            tot_fail_ctr: None,
            spent_time_ctr: None,
            raw: body.to_vec(),
        });
    }
    let rest_start = 2usize.checked_add(num_keys as usize)?;
    if body.len() < rest_start {
        return None;
    }
    let key_versions = body.get(2..rest_start)?.to_vec();
    let rest = body.get(rest_start..)?;
    let be16 = |slice: &[u8]| -> Option<u16> {
        let pair: [u8; 2] = slice.get(..2)?.try_into().ok()?;
        Some(u16::from_be_bytes(pair))
    };
    let (seq_fail_ctr, tot_fail_ctr, spent_time_ctr) = if rest.len() >= 5 {
        (
            rest.first().map(|v| *v as u16),
            be16(rest.get(1..)?),
            be16(rest.get(3..)?),
        )
    } else {
        (None, None, None)
    };
    Some(Budget {
        key_settings,
        num_keys,
        key_versions,
        core_trusted: true,
        seq_fail_ctr,
        tot_fail_ctr,
        spent_time_ctr,
        raw: body.to_vec(),
    })
}

pub async fn cmd_budget<T: Transport>(transport: &mut T, json_mode: bool) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let uid = Session::default()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    let uid_hex = crate::to_hex(uid);

    let resp = transport
        .transmit(GET_KEY_SETTINGS)
        .await
        .context("GetKeySettings transmit failed")?;
    crate::audit::log_event(&format!("budget: UID={uid_hex}"));

    if resp.sw1 != 0x91 || resp.sw2 != 0x00 {
        anyhow::bail!(
            "GetKeySettings rejected (SW={:02X}{:02X}) — not an NTAG424-family card?",
            resp.sw1,
            resp.sw2
        );
    }

    let parsed = parse_budget(resp.data.as_ref()).ok_or_else(|| {
        anyhow::anyhow!(
            "GetKeySettings response too short to parse: {} bytes",
            resp.data.as_ref().len()
        )
    })?;

    if json_mode {
        let raw_hex = crate::to_hex(parsed.raw.clone());
        let json = if parsed.core_trusted {
            format!(
                r#"{{"ok":true,"uid":"{uid_hex}","core_trusted":true,"key_settings":{},"num_keys":{},"key_versions":[{}],"seq_fail_ctr":{},"tot_fail_ctr":{},"spent_time_ctr":{},"raw":"{raw_hex}"}}"#,
                parsed.key_settings,
                parsed.num_keys,
                parsed
                    .key_versions
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                parsed
                    .seq_fail_ctr
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".into()),
                parsed
                    .tot_fail_ctr
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".into()),
                parsed
                    .spent_time_ctr
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".into()),
            )
        } else {
            format!(
                r#"{{"ok":true,"uid":"{uid_hex}","core_trusted":false,"raw":"{raw_hex}"}}"#
            )
        };
        println!("{json}");
        return Ok(());
    }

    println!("Card UID: {uid_hex}");
    if !parsed.core_trusted {
        println!(
            "Response does not match the DESFire core (NumKeys={:#04X}) — raw only:",
            parsed.num_keys
        );
        println!("Raw: {}", crate::to_hex(parsed.raw.clone()));
        return Ok(());
    }
    println!(
        "KeySettings: 0x{:02X}  NumKeys: {}",
        parsed.key_settings, parsed.num_keys
    );
    println!(
        "Key versions: {}",
        parsed
            .key_versions
            .iter()
            .map(|v| format!("{v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    match (
        parsed.seq_fail_ctr,
        parsed.tot_fail_ctr,
        parsed.spent_time_ctr,
    ) {
        (Some(seq), Some(tot), Some(time)) => {
            println!("SeqFailCtr:    {seq}/50   (delay ladder; resets on success)");
            println!("TotFailCtr:  {tot}/1000 (PERMANENT key lock at 1000 — ChangeKey only)");
            println!("SpentTimeCtr: {time}");
            if tot >= 900 {
                println!("⚠️  near permanent lock — STOP authenticating this card");
            }
        }
        _ => println!("Counters: not present in this response shape"),
    }
    println!(
        "Raw: {}  (counter-trailer layout live-verification pending)",
        crate::to_hex(parsed.raw)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_budget;

    #[test]
    fn parses_core_and_counters() {
        // settings, numkeys=5, versions, counters
        let body = [0x00, 0x05, 1, 2, 3, 4, 5, 32, 0x01, 0x00, 0x02, 0x00];
        let b = parse_budget(&body).expect("parses");
        assert_eq!(b.key_settings, 0x00);
        assert_eq!(b.num_keys, 5);
        assert_eq!(b.key_versions, vec![1, 2, 3, 4, 5]);
        assert_eq!(b.seq_fail_ctr, Some(32));
        assert_eq!(b.tot_fail_ctr, Some(0x0100));
        assert_eq!(b.spent_time_ctr, Some(0x0200));
    }

    #[test]
    fn tolerates_core_only_response() {
        let body = [0x40, 0x03, 9, 9, 9];
        let b = parse_budget(&body).expect("parses");
        assert_eq!(b.key_versions.len(), 3);
        assert_eq!(b.seq_fail_ctr, None);
    }

    #[test]
    fn marks_nonsensical_core_untrusted_but_keeps_raw() {
        // 19-byte capture shape (2026-08 session): NumKeys byte 0x40
        // cannot be a key count, so the core is untrusted — raw survives.
        let body = [
            0x00, 0x40, 0x00, 0xE0, 0x00, 0x01, 0x00, 0xC1, 0xFF, 0x12, 0x5C, 0x00, 0x00, 0x7F,
            0x00, 0x00, 0x7F, 0x00, 0x00,
        ];
        let b = parse_budget(&body).expect("parses");
        assert!(!b.core_trusted);
        assert_eq!(b.num_keys, 0x40);
        assert!(b.key_versions.is_empty());
        assert_eq!(b.seq_fail_ctr, None);
        assert_eq!(b.raw.len(), 19);
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse_budget(&[0x00]).is_none());
        assert!(parse_budget(&[]).is_none());
    }
}
