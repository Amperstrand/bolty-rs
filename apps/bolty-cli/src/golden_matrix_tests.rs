//! Host-side replay of the ACR1252 golden-response recording against the
//! mock NTAG424 transport (#73 graduation wave 3, candidate 3).
//!
//! `tools/hil/difftest/generated/test_golden_responses.py` holds 63
//! (apdu, response, sw) rows recorded from a real card through the ACR1252
//! reference reader. Until now nothing enforced them — the python file is
//! an offline structure check only. This runner replays the matrix IN
//! ORDER against ONE `MockTransport` (mirroring the capture session) and
//! byte-compares (response, SW). Mock/hardware divergence — the dominant
//! bug class per the Reference-First Doctrine — becomes a host-CI failure.
//!
//! Split, don't delete (#73 rubric G3/G5): rows whose recorded bytes
//! depend on capture-session file-selection sequencing that cannot be
//! reconstructed from the recording alone are DOCUMENTED skips, not
//! guessed mock behavior. The two-reader differential (`make difftest`)
//! keeps proving the live half bench-side.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use bolty_ntag::Transport as _;

use crate::mock_transport::MockTransport;

/// Golden card from the capture header (golden_responses.h / the python
/// docstring). The mock's default UID is the bolty-ntag fixture card;
/// `set_uid` pins it to the recorded card so `get_uid` compares exactly.
const GOLDEN_CARD_UID: [u8; 7] = [0x04, 0xC4, 0x74, 0xFA, 0x96, 0x73, 0x80];

/// Rows skipped because their recorded bytes are capture-session
/// artifacts: the CC-read family and Le-edge rows were recorded with a
/// file-selection state the recording cannot reconstruct (e.g. CC data
/// returned after an NDEF EF select; the `stress_read_cc_10x` family all
/// 6985), and re-recording needs the bench. When a fresh capture lands,
/// shrink this list — never hardcode the recorded quirks as mock state.
const SESSION_ARTIFACT_ROWS: &[&str] = &[
    "read_cc_full",
    "read_cc_partial",
    "read_cc_invalid_offset",
    "read_no_select",
    "malformed_le_zero",
    "malformed_le_max",
    "stress_read_cc_10x",
    "stress_read_cc_10x_r1",
    "stress_read_cc_10x_r2",
    "stress_read_cc_10x_r3",
    "stress_read_cc_10x_r4",
    "stress_read_cc_10x_r5",
    "stress_read_cc_10x_r6",
    "stress_read_cc_10x_r7",
    "stress_read_cc_10x_r8",
    "stress_read_cc_10x_r9",
];

struct GoldenRow {
    test_id: String,
    apdu: Vec<u8>,
    response: Vec<u8>,
    sw: u16,
}

fn parse_golden_matrix() -> Vec<GoldenRow> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/hil/difftest/generated/test_golden_responses.py"
    );
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("golden matrix unreadable ({path}): {e}"));

    let mut rows = Vec::new();
    for line in src.lines() {
        let Some(rest) = line.trim_start().strip_prefix("(\"") else {
            continue;
        };
        // ("id", "apdu", "response", "sw", "description"),
        let mut fields = Vec::new();
        let mut rest = rest;
        while let Some(close) = rest.find("\", \"") {
            fields.push(rest[..close].to_string());
            rest = &rest[close + 4..];
        }
        // Last field before the closing `")` of the description tuple.
        let Some(close) = rest.find("\")") else {
            continue;
        };
        fields.push(rest[..close].to_string());
        if fields.len() != 5 {
            continue;
        }
        let sw = u16::from_str_radix(&fields[3], 16)
            .unwrap_or_else(|e| panic!("bad SW {:?}: {e}", fields[3]));
        rows.push(GoldenRow {
            test_id: fields[0].clone(),
            apdu: decode_hex(&fields[1]),
            response: decode_hex(&fields[2]),
            sw,
        });
    }
    rows
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("golden hex is well-formed"))
        .collect()
}

#[tokio::test]
async fn golden_matrix_replays_against_mock() {
    let rows = parse_golden_matrix();
    assert!(
        rows.len() >= 60,
        "golden matrix shrank unexpectedly: {} rows",
        rows.len()
    );

    let skipped: HashSet<&str> = SESSION_ARTIFACT_ROWS.iter().copied().collect();

    let mut mock = MockTransport::new();
    mock.set_uid(GOLDEN_CARD_UID);

    let mut checked = 0;
    for row in &rows {
        if skipped.contains(row.test_id.as_str()) {
            continue;
        }
        let resp = mock
            .transmit(&row.apdu)
            .await
            .expect("mock transport is infallible");
        let sw = (u16::from(resp.sw1) << 8) | u16::from(resp.sw2);
        assert_eq!(
            (resp.data.as_slice(), sw),
            (row.response.as_slice(), row.sw),
            "golden row {}: mock diverged from the ACR1252 recording",
            row.test_id
        );
        checked += 1;
    }
    assert_eq!(checked, rows.len() - skipped.len());
}

#[test]
fn session_artifact_skip_list_stays_honest() {
    let rows = parse_golden_matrix();
    let ids: HashSet<&str> = rows.iter().map(|r| r.test_id.as_str()).collect();
    for id in SESSION_ARTIFACT_ROWS {
        assert!(
            ids.contains(id),
            "skip-list row {id} no longer exists in the golden matrix — prune it"
        );
    }
}
