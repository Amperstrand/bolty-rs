//! Rig-facing SUN read path — the consumption contract for the boltcard
//! test rig (boltcard-rig lane on ai-legion owns card-emulation + worker;
//! bolty-rs is the reader/verification side).
//!
//! `bolty_core::picc` is pure host-side logic (no esp-idf, no PCSC): the
//! rig consumes it as a library. This example pins that contract from the
//! command line — same function the firmware's `picc` command and the
//! CLI's `inspect` SDM path call.
//!
//! Run:
//! ```text
//! cargo run -p bolty-core --example picc_verify -- \
//!     55DA174C9608993DC27BB3F30A4A7314 2AB74ABC1273FB43CAE97553A36D4D08 \
//!     'https://example.com/bolt?p=E61CB056F52D34F9368F079D1814D2CF&c=FCC9A22201EA2298'
//! ```
//! Exit 0 + `valid=true` = SUN authentication consumed successfully
//! (p decrypted to a well-formed PICCData AND the c= CMAC verified).

use bolty_core::picc::picc_parse_url;
use bolty_core::util::decode_hex;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!(
            "usage: picc_verify <k1-hex-32> <k2-hex-32> <url>...\n\
             \x20 k1 = SDM Meta Read Access Key (p= decryption)\n\
             \x20 k2 = SDM File Read Access Key (c= CMAC verification)"
        );
        std::process::exit(2);
    }

    let k1 = match decode_hex(&args[0]).map(|v| <[u8; 16]>::try_from(v)) {
        Ok(Ok(k)) => k,
        _ => {
            eprintln!("k1 must be 32 hex chars (16 bytes)");
            std::process::exit(2);
        }
    };
    let k2 = match decode_hex(&args[1]).map(|v| <[u8; 16]>::try_from(v)) {
        Ok(Ok(k)) => k,
        _ => {
            eprintln!("k2 must be 32 hex chars (16 bytes)");
            std::process::exit(2);
        }
    };

    let mut any_invalid = false;
    for url in &args[2..] {
        let picc = picc_parse_url(&k1, &k2, url);
        println!("{url} -> {picc:?}");
        if !picc.valid {
            any_invalid = true;
        }
    }
    std::process::exit(i32::from(any_invalid));
}
