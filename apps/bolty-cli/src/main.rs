#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod audit;
pub(crate) mod burn;
mod common;
mod diagnose;
mod inspect;
mod keyver;
#[cfg(test)]
#[path = "mock_transport.rs"]
mod mock_transport;
mod picc;
mod scan_keys;
mod testck;
mod transport;
mod try_key;
mod ver;
mod wipe;

use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use bolty_core::util::decode_hex;
use clap::Parser;

#[derive(Parser)]
#[command(name = "bolty-cli", about = "NTAG424 card programming CLI via PCSC")]
struct Args {
    /// Output machine-readable JSON instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Cli,
}

#[derive(Parser)]
enum Cli {
    /// Read and print the card UID
    Uid,

    /// Read and print hardware/software version info (unauthenticated)
    Ver,

    /// Read key versions from all 5 key slots (requires K0 authentication)
    Keyver {
        #[arg(long)]
        issuer_key: String,

        #[arg(long, default_value = "1")]
        version: u8,
    },

    /// Inspect card: UID, version, file settings, NDEF content
    Inspect {
        /// Issuer key for authenticated reads + SDM decryption (32 hex chars)
        #[arg(long)]
        issuer_key: Option<String>,

        #[arg(long, default_value = "1")]
        version: u8,

        /// Print derived key material and SDM details
        #[arg(long)]
        verbose: bool,
    },

    /// Extract the live NDEF URL from the card
    Url,

    /// Burn card: write SDM NDEF, enable SDM, install derived keys
    Burn {
        #[arg(long)]
        issuer_key: String,

        #[arg(long)]
        url: String,

        #[arg(long, default_value = "1")]
        version: u8,

        /// Print derived key material to stdout
        #[arg(long)]
        verbose: bool,

        /// Preview planned actions without sending any APDUs
        #[arg(long)]
        dry_run: bool,

        /// Require this UID (14 hex chars) before proceeding — safety against wrong card
        #[arg(long)]
        confirm_uid: Option<String>,

        /// Bypass safety checks (state guard, URL validation)
        #[arg(long)]
        force: bool,
    },

    /// Wipe card: clear SDM, reset all keys to factory defaults
    Wipe {
        #[arg(long)]
        issuer_key: String,

        #[arg(long, default_value = "1")]
        version: u8,

        /// Print derived key material to stdout
        #[arg(long)]
        verbose: bool,

        /// Preview planned actions without sending any APDUs
        #[arg(long)]
        dry_run: bool,

        /// Require this UID (14 hex chars) before proceeding — safety against wrong card
        #[arg(long)]
        confirm_uid: Option<String>,
    },

    /// Full burn → wipe → re-burn cycle with verification at each step
    Cycle {
        #[arg(long)]
        issuer_key: String,

        #[arg(long)]
        url: String,

        #[arg(long, default_value = "1")]
        version: u8,

        /// Print derived key material to stdout
        #[arg(long)]
        verbose: bool,
    },

    /// Read-only PICC data decryption: extract p=/c= from NDEF and verify locally.
    /// No authentication APDUs sent — zero risk of bricking or auth-delay.
    Picc {
        #[arg(long)]
        issuer_key: String,
    },

    /// Diagnose card state: BLANK / PROVISIONED / HALF-WIPED / AUTH_DELAY / INCONSISTENT.
    /// Read-only except for a single factory K0 probe on blank-looking cards.
    Diagnose {
        #[arg(long)]
        issuer_key: String,
    },

    /// Compute and print derived keys (no card needed)
    DeriveKeys {
        #[arg(long)]
        uid: String,

        #[arg(long)]
        issuer_key: String,

        #[arg(long, default_value = "1")]
        version: u8,

        /// Print derived key material to stdout
        #[arg(long)]
        verbose: bool,
    },

    /// Try a raw AES key against a specific key slot (read-only, no writes).
    /// Useful for card recovery when you don't know which key is on the card.
    TryKey {
        /// Raw 16-byte key in hex (32 chars)
        #[arg(long)]
        key: String,

        /// Key slot to test (0-4, default 0 = master key)
        #[arg(long, default_value = "0")]
        key_no: u8,
    },

    /// Scan all likely key candidates against K0 (read-only, no writes).
    /// Tries factory zeros, derived K0 v0-v3, static test keys, and card key.
    /// Stops on first match or auth delay.
    ScanKeys {
        #[arg(long)]
        issuer_key: String,
    },

    /// Power-cycle the card to clear auth delay (SCARD_UNPOWER_CARD).
    /// Resets SeqFailCtr (volatile). Does NOT reset TotFailCtr.
    ResetCard,

    /// Verify ChangeKey implementation — round-trip key 1 zero→test→zero.
    /// Requires BLANK card (factory K0 = zeros).
    TestCk,
}

fn parse_hex_16(s: &str) -> anyhow::Result<[u8; 16]> {
    decode_hex::<16>(s.trim()).map_err(|e| anyhow::anyhow!("{e}"))
}

fn parse_hex_7(s: &str) -> anyhow::Result<[u8; 7]> {
    decode_hex::<7>(s.trim()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// SAFETY: b is u8, so b>>4 ∈ 0..16 and b&0xf ∈ 0..16; HEX has 16 elements.
#[allow(clippy::indexing_slicing)]
fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    bolty_core::util::encode_hex(bytes.as_ref())
}

fn connect_transport() -> anyhow::Result<audit::LoggingTransport<transport::PcscTransport>> {
    let t = transport::PcscTransport::connect()?;
    println!("Connected to reader: {}", t.reader_name());
    Ok(audit::LoggingTransport::new(t))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e:#}");
        let code = exit_code_for(&e);
        std::process::exit(code);
    }
}

fn exit_code_for(e: &anyhow::Error) -> i32 {
    for cause in e.chain() {
        if let Some(err) = cause.downcast_ref::<transport::PcscError>() {
            return match err {
                transport::PcscError::NoReaders => {
                    eprintln!("Hint: connect a PCSC smart card reader.");
                    2
                }
                transport::PcscError::NoCardInReader(_) => {
                    eprintln!("Hint: place an NTAG424 card on the reader.");
                    3
                }
                _ => 4,
            };
        }
        if cause.downcast_ref::<bolty_core::util::HexError>().is_some() {
            eprintln!("Hint: hex strings must use only 0-9 a-f A-F with the correct length.");
            return 5;
        }
    }
    1
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let json_mode = args.json;
    let cli = args.command;

    match cli {
        Cli::Uid => {
            let mut transport = connect_transport()?;
            inspect::cmd_uid(&mut transport).await?;
        }

        Cli::Ver => {
            let mut transport = connect_transport()?;
            ver::cmd_ver(&mut transport).await?;
        }

        Cli::Keyver {
            issuer_key,
            version,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;
            keyver::cmd_keyver(&mut transport, &issuer_key, version).await?;
        }

        Cli::Inspect {
            issuer_key,
            version,
            verbose,
        } => {
            let mut transport = connect_transport()?;
            let issuer_key = issuer_key.map(|s| parse_hex_16(&s)).transpose()?;
            inspect::cmd_inspect(&mut transport, issuer_key, version, verbose).await?;
        }

        Cli::Url => {
            let mut transport = connect_transport()?;
            inspect::cmd_url(&mut transport).await?;
        }

        Cli::Burn {
            issuer_key,
            url,
            version,
            verbose,
            dry_run,
            confirm_uid,
            force,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let confirm_uid = confirm_uid.map(|s| parse_hex_7(&s)).transpose()?;
            let mut transport = connect_transport()?;
            burn::cmd_burn(
                &mut transport,
                &issuer_key,
                &url,
                version,
                verbose,
                dry_run,
                confirm_uid.as_ref(),
                force,
            )
            .await?;
        }

        Cli::Wipe {
            issuer_key,
            version,
            verbose,
            dry_run,
            confirm_uid,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let confirm_uid = confirm_uid.map(|s| parse_hex_7(&s)).transpose()?;
            let mut transport = connect_transport()?;
            wipe::cmd_wipe(
                &mut transport,
                &issuer_key,
                version,
                verbose,
                dry_run,
                confirm_uid.as_ref(),
            )
            .await?;
        }

        Cli::Picc { issuer_key } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;
            picc::cmd_picc(&mut transport, &issuer_key).await?;
        }

        Cli::Diagnose { issuer_key } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;
            diagnose::cmd_diagnose(&mut transport, &issuer_key, json_mode).await?;
        }

        Cli::DeriveKeys {
            uid,
            issuer_key,
            version,
            verbose,
        } => {
            let uid = parse_hex_7(&uid)?;
            let issuer_key = parse_hex_16(&issuer_key)?;
            let keys = BoltcardDeterministicDeriver::derive_keys(
                &issuer_key,
                CardUid::new(uid),
                version as u32,
            );
            if verbose {
                println!("Derived keys (version {version}):");
                println!("  cardKey: {}", to_hex(keys.card_key.as_bytes()));
                println!("  K0:      {}", to_hex(keys.k0.as_bytes()));
                println!("  K1:      {}", to_hex(keys.k1.as_bytes()));
                println!("  K2:      {}", to_hex(keys.k2.as_bytes()));
                println!("  K3:      {}", to_hex(keys.k3.as_bytes()));
                println!("  K4:      {}", to_hex(keys.k4.as_bytes()));
            } else {
                println!("Keys derived (version {version}). Use --verbose to display.");
            }
        }

        Cli::Cycle {
            issuer_key,
            url,
            version,
            verbose,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;

            println!("═══ CYCLE: BURN ═══");
            burn::cmd_burn(
                &mut transport,
                &issuer_key,
                &url,
                version,
                verbose,
                false,
                None,
                false,
            )
            .await?;

            println!("\n═══ CYCLE: WIPE ═══");
            wipe::cmd_wipe(&mut transport, &issuer_key, version, verbose, false, None).await?;

            println!("\n═══ CYCLE: RE-BURN ═══");
            burn::cmd_burn(
                &mut transport,
                &issuer_key,
                &url,
                version,
                verbose,
                false,
                None,
                false,
            )
            .await?;

            println!("\n🎉 Full cycle completed successfully!");
        }

        Cli::TryKey { key, key_no } => {
            let key = parse_hex_16(&key)?;
            let mut transport = connect_transport()?;
            try_key::cmd_try_key(&mut transport, &key, key_no).await?;
        }

        Cli::ScanKeys { issuer_key } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;
            scan_keys::cmd_scan_keys(&mut transport, &issuer_key).await?;
        }

        Cli::ResetCard => {
            let mut transport = connect_transport()?;
            println!("Clearing auth delay via 'keep trying' (rapid AuthFirst)...");
            println!("Per NT4H2421Gx datasheet: 'Keep trying until full delay is spent'");
            try_key::cmd_try_key(&mut transport, &[0u8; 16], 0).await?;
        }

        Cli::TestCk => {
            let mut transport = connect_transport()?;
            testck::cmd_testck(&mut transport).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_hex_7, parse_hex_16};

    // ── parse_hex_16 ───────────────────────────────────────────────

    #[test]
    fn hex16_valid() {
        let result = parse_hex_16("00000000000000000000000000000001").unwrap();
        assert_eq!(result[15], 1);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn hex16_valid_uppercase() {
        let result = parse_hex_16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        assert_eq!(result, [0xFFu8; 16]);
    }

    #[test]
    fn hex16_valid_mixed_case() {
        let result = parse_hex_16("DeAdBeEf0000000000000000000000FF").unwrap();
        assert_eq!(result[0], 0xDE);
        assert_eq!(result[3], 0xEF);
        assert_eq!(result[15], 0xFF);
    }

    #[test]
    fn hex16_trims_whitespace() {
        let result = parse_hex_16("  00000000000000000000000000000001  ").unwrap();
        assert_eq!(result[15], 1);
    }

    #[test]
    fn hex16_too_short() {
        assert!(parse_hex_16("0001").is_err());
    }

    #[test]
    fn hex16_too_long() {
        assert!(parse_hex_16("0000000000000000000000000000000100").is_err());
    }

    #[test]
    fn hex16_invalid_chars() {
        assert!(parse_hex_16("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }

    #[test]
    fn hex16_empty() {
        assert!(parse_hex_16("").is_err());
    }

    // ── parse_hex_7 ────────────────────────────────────────────────

    #[test]
    fn hex7_valid() {
        let result = parse_hex_7("04a39493cc8680").unwrap();
        assert_eq!(result, [0x04, 0xA3, 0x94, 0x93, 0xCC, 0x86, 0x80]);
    }

    #[test]
    fn hex7_valid_uppercase() {
        let result = parse_hex_7("04A39493CC8680").unwrap();
        assert_eq!(result[0], 0x04);
    }

    #[test]
    fn hex7_trims_whitespace() {
        let result = parse_hex_7("  04a39493cc8680  ").unwrap();
        assert_eq!(result[0], 0x04);
    }

    #[test]
    fn hex7_too_short() {
        assert!(parse_hex_7("04a394").is_err());
    }

    #[test]
    fn hex7_too_long() {
        assert!(parse_hex_7("04a39493cc8680ff").is_err());
    }

    #[test]
    fn hex7_invalid_chars() {
        assert!(parse_hex_7("XXa39493cc8680").is_err());
    }

    #[test]
    fn hex7_empty() {
        assert!(parse_hex_7("").is_err());
    }
}
