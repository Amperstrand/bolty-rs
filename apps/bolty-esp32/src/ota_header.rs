//! OTA wire-protocol header + token authorization (pure logic,
//! host-testable; the TCP/flash server lives in `ota_server.rs`, esp
//! targets only).
//!
//! Port of ccid-firmware-rs `firmware/esp32-ccid/src/ota_header.rs`
//! (Amperstrand, GPL-2.0-or-later — the "or later" permits this copy into
//! bolty's GPL-3.0-or-later tree), #494 audit adoption item (a): today any
//! LAN peer can flash a nucula over the :3232 push server; the token
//! exchange is the bench-tier floor the audit demands (§2.4 "Authenticate
//! before bytes").
//!
//! Two header shapes share the 4-byte magic slot:
//! - `OTA1` + u32-LE size (8 bytes) — the original, tokenless form
//! - `OTA2` + u32-LE size + 32-byte token (40 bytes) — authenticated form
//!
//! Compile-time token: `OTA_TOKEN=<exactly 32 chars>` at build time arms
//! the server (same env-var discipline as the wifi credentials). Arming
//! rules:
//! - server armed + `OTA2` + matching token → accepted
//! - server armed + `OTA2` + wrong token   → refused (loud, pre-flash)
//! - server armed + `OTA1`                 → refused ("this build requires
//!   a token") — a tokenless client must never flash an armed build
//! - server unarmed + `OTA1`               → accepted (today's behavior)
//! - server unarmed + `OTA2`               → accepted, token ignored
//!   (forward compatibility: old firmware, newer client)
//!
//! Mismatches fail at the MAGIC/token stage before any image byte is read
//! — no corruption window, both directions loud. Host client: ccid
//! `tests/hardware/vpcd/ota_push.py` (OTA1/OTA2-aware).

pub const MAGIC_V1: [u8; 4] = *b"OTA1";
pub const MAGIC_V2: [u8; 4] = *b"OTA2";
pub const TOKEN_LEN: usize = 32;

pub type Token = [u8; TOKEN_LEN];

/// Announced-size gate (pure logic, ccid #223): validated against the
/// ACTUAL OTA partition size before any erase/write — `0` is never a
/// valid app image, and an image larger than the target partition can
/// never succeed.
pub fn validate_size(announced: usize, partition_size: usize) -> Result<(), &'static str> {
    if announced == 0 {
        Err("bad size")
    } else if announced > partition_size {
        Err("announced image larger than the OTA partition")
    } else {
        Ok(())
    }
}

#[cfg_attr(
    not(all(
        any(target_arch = "xtensa", target_arch = "riscv32"),
        feature = "ota-server"
    )),
    allow(dead_code)
)]
pub fn compiled_token() -> Option<Token> {
    let tok = option_env!("OTA_TOKEN")?;
    let bytes = tok.as_bytes();
    if bytes.len() != TOKEN_LEN {
        // A wrong-length build-time token cannot be matched on the wire;
        // treating it as unarmed would SILENTLY disable auth — fail loudly
        // at runtime instead (build.rs-style validation is overkill here).
        panic!(
            "OTA_TOKEN must be exactly {TOKEN_LEN} bytes, got {}",
            bytes.len()
        );
    }
    Some(
        *bytes
            .first_chunk::<TOKEN_LEN>()
            .expect("length checked above"),
    )
}

#[cfg_attr(
    not(all(
        any(target_arch = "xtensa", target_arch = "riscv32"),
        feature = "ota-server"
    )),
    allow(dead_code)
)]
pub fn authorize(
    magic: &[u8; 4],
    token: Option<&Token>,
    expected: Option<&Token>,
) -> Result<(), &'static str> {
    match (*magic == MAGIC_V2, expected) {
        (true, Some(want)) => {
            let got = token.ok_or("OTA2 header missing token payload")?;
            if got == want {
                Ok(())
            } else {
                Err("OTA token mismatch")
            }
        }
        (true, None) => Ok(()),
        (false, Some(_)) => Err("OTA1 refused: this build requires a token (use OTA2)"),
        (false, None) => {
            if magic == &MAGIC_V1 {
                Ok(())
            } else {
                Err("bad magic")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOK: Token = [0xA5; TOKEN_LEN];

    #[test]
    fn v1_unarmed_accepts_the_original_protocol() {
        assert!(authorize(&MAGIC_V1, None, None).is_ok());
    }

    #[test]
    fn v2_matching_token_accepts() {
        assert!(authorize(&MAGIC_V2, Some(&TOK), Some(&TOK)).is_ok());
    }

    #[test]
    fn v2_wrong_token_is_refused() {
        let bad = [!0xA5; TOKEN_LEN];
        assert_eq!(
            authorize(&MAGIC_V2, Some(&bad), Some(&TOK)),
            Err("OTA token mismatch")
        );
    }

    #[test]
    fn v2_missing_token_is_refused_when_armed() {
        assert_eq!(
            authorize(&MAGIC_V2, None, Some(&TOK)),
            Err("OTA2 header missing token payload")
        );
    }

    #[test]
    fn v1_is_refused_when_armed() {
        // A tokenless client must never flash an armed build — the whole
        // point of item (a).
        assert_eq!(
            authorize(&MAGIC_V1, None, Some(&TOK)),
            Err("OTA1 refused: this build requires a token (use OTA2)")
        );
    }

    #[test]
    fn v2_token_ignored_when_unarmed() {
        // Forward compatibility: old firmware, newer client.
        assert!(authorize(&MAGIC_V2, Some(&TOK), None).is_ok());
        assert!(authorize(&MAGIC_V2, None, None).is_ok());
    }

    #[test]
    fn unknown_magic_refused() {
        assert_eq!(authorize(b"XXXX", None, None), Err("bad magic"));
    }

    #[test]
    fn size_gate_rejects_zero_and_oversize_accepts_fitting() {
        assert_eq!(validate_size(0, 0x140000), Err("bad size"));
        assert_eq!(
            validate_size(0x140001, 0x140000),
            Err("announced image larger than the OTA partition")
        );
        assert!(validate_size(0x140000, 0x140000).is_ok());
        // The nucula image class (~898 KiB) against the dual-slot table.
        assert!(validate_size(919_616, 0x140000).is_ok());
    }
}
