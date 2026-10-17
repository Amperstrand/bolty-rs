//! User-facing output contract — the exact strings the HIL suite greps.
//!
//! `tools/hil/tests/test_burn_lock_wipe.py` asserts on substrings of these
//! strings (bench-only evidence today). The test below binds every const to
//! the literal in that file, so re-wording or re-spacing CLI output breaks
//! HOST CI instead of wasting a bench burn cycle (#73 graduation candidate
//! 2: split, don't delete — the bench twin keeps proving the silicon half).

/// Burn success line. HIL greps `burned and verified successfully`.
pub const BURN_OK: &str = "✅ Card burned and verified successfully!";

/// Wipe success line. HIL greps `wiped and verified successfully`.
pub const WIPE_OK: &str = "✅ Card wiped and verified successfully!";

/// Wipe pre-verification gate banner. HIL greps `Pre-verifying p/c (DET:57-59)`.
pub const WIPE_PREVERIFY: &str = "Pre-verifying p/c (DET:57-59)...";

/// Wipe gate success line. HIL greps `✓ p/c verified`.
pub const WIPE_PC_VERIFIED: &str = "  ✓ p/c verified (UID + counter + SUN MAC valid)";

/// Diagnose card-state label — spacing is load-bearing (HIL greps the
/// composed `Card state:     BLANK`, five spaces).
pub const DIAG_CARD_STATE_LABEL: &str = "Card state:     ";

/// Diagnose state: factory keys, no SDM, empty NDEF.
pub const CARD_STATE_BLANK: &str = "BLANK";

/// Diagnose state: SDM active, NDEF content, PICC verifies.
pub const CARD_STATE_PROVISIONED: &str = "PROVISIONED";

/// Inspect SDM line prefix; the bool renders Rust-style. HIL greps
/// `CMAC_valid=true`.
pub const CMAC_VALID_PREFIX: &str = "CMAC_valid=";

#[cfg(test)]
mod tests {
    use super::*;

    /// The grep literals `test_burn_lock_wipe.py` asserts on (verbatim),
    /// each bound to the CLI const that must contain them. If the python
    /// side re-words a grep, this fails HERE first — the two sides move
    /// together or not at all.
    #[test]
    fn hil_grep_literals_match_cli_output_contract() {
        let hil = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/hil/tests/test_burn_lock_wipe.py"
        ))
        .expect("HIL suite file missing — has tools/hil/tests moved?");

        let card_state_blank = format!("{DIAG_CARD_STATE_LABEL}{CARD_STATE_BLANK}");
        let cmac_valid_true = format!("{CMAC_VALID_PREFIX}{}", true);

        let bindings: &[(&str, &str)] = &[
            ("grep literal", "CLI const"),
            ("burned and verified successfully", BURN_OK),
            ("wiped and verified successfully", WIPE_OK),
            ("Pre-verifying p/c (DET:57-59)", WIPE_PREVERIFY),
            ("✓ p/c verified", WIPE_PC_VERIFIED),
            ("Card state:     BLANK", &card_state_blank),
            ("PROVISIONED", CARD_STATE_PROVISIONED),
            ("CMAC_valid=true", &cmac_valid_true),
        ];

        for (literal, cli_output) in bindings.iter().skip(1) {
            assert!(
                hil.contains(literal),
                "HIL suite no longer greps {literal:?} — update this contract or the HIL test \
                 together (they are one contract, two sides)"
            );
            assert!(
                cli_output.contains(literal),
                "CLI output no longer contains the HIL grep literal {literal:?} — the bench \
                 test would fail on hardware; fix the const or the HIL grep together"
            );
        }
    }

    /// The label's spacing is the historic accident the bench greps depend
    /// on — lock it independently of the python file too.
    #[test]
    fn diagnose_card_state_label_spacing_is_pinned() {
        assert_eq!(DIAG_CARD_STATE_LABEL.len(), "Card state:".len() + 5);
        assert_eq!(DIAG_CARD_STATE_LABEL, "Card state:     ");
    }
}
