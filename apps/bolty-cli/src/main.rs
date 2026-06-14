mod burn;
mod transport;

use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::util::decode_hex;
use clap::Parser;

#[derive(Parser)]
#[command(name = "bolty-cli", about = "NTAG424 card programming CLI via PCSC")]
enum Cli {
    /// Read and print the card UID
    Uid,

    /// Inspect card: UID, version, file settings, NDEF content (unauthenticated)
    Inspect,

    /// Burn card: write SDM NDEF, enable SDM, install derived keys
    Burn {
        /// Issuer key as 32-char hex string (16 bytes)
        #[arg(long)]
        issuer_key: String,

        /// SDM URL template (e.g. https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac})
        #[arg(long)]
        url: String,

        /// Key version byte (default: 1)
        #[arg(long, default_value = "1")]
        version: u8,
    },

    /// Wipe card: clear SDM, reset all keys to factory defaults
    Wipe {
        /// Issuer key as 32-char hex string (16 bytes)
        #[arg(long)]
        issuer_key: String,

        /// Key version byte (must match the version used during burn)
        #[arg(long, default_value = "1")]
        version: u8,
    },

    /// Full burn → wipe → re-burn cycle with verification at each step
    Cycle {
        /// Issuer key as 32-char hex string (16 bytes)
        #[arg(long)]
        issuer_key: String,

        /// SDM URL template (e.g. https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac})
        #[arg(long)]
        url: String,

        /// Key version byte (default: 1)
        #[arg(long, default_value = "1")]
        version: u8,
    },

    /// Compute and print derived keys (no card needed)
    DeriveKeys {
        /// Card UID as 14-char hex string (7 bytes)
        #[arg(long)]
        uid: String,

        /// Issuer key as 32-char hex string (16 bytes)
        #[arg(long)]
        issuer_key: String,

        /// Key version (default: 1)
        #[arg(long, default_value = "1")]
        version: u8,
    },
}

fn parse_hex_16(s: &str) -> anyhow::Result<[u8; 16]> {
    decode_hex::<16>(s.trim()).ok_or_else(|| anyhow::anyhow!("expected 32 hex chars (16 bytes)"))
}

fn parse_hex_7(s: &str) -> anyhow::Result<[u8; 7]> {
    decode_hex::<7>(s.trim()).ok_or_else(|| anyhow::anyhow!("expected 14 hex chars (7 bytes)"))
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let bytes = bytes.as_ref();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn connect_transport() -> anyhow::Result<transport::PcscTransport> {
    let t = transport::PcscTransport::connect()?;
    println!("Connected to reader: {}", t.reader_name());
    Ok(t)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Uid => {
            let mut transport = connect_transport()?;
            burn::cmd_uid(&mut transport).await?;
        }

        Cli::Inspect => {
            let mut transport = connect_transport()?;
            burn::cmd_inspect(&mut transport).await?;
        }

        Cli::Burn {
            issuer_key,
            url,
            version,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;
            burn::cmd_burn(&mut transport, &issuer_key, &url, version).await?;
        }

        Cli::Wipe {
            issuer_key,
            version,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;
            burn::cmd_wipe(&mut transport, &issuer_key, version).await?;
        }

        Cli::DeriveKeys {
            uid,
            issuer_key,
            version,
        } => {
            let uid = parse_hex_7(&uid)?;
            let issuer_key = parse_hex_16(&issuer_key)?;
            let keys = BoltcardDeterministicDeriver::derive_keys(&issuer_key, &uid, version as u32);
            println!("Derived keys (version {version}):");
            println!("  cardKey: {}", to_hex(keys.card_key));
            println!("  K0:      {}", to_hex(keys.k0));
            println!("  K1:      {}", to_hex(keys.k1));
            println!("  K2:      {}", to_hex(keys.k2));
            println!("  K3:      {}", to_hex(keys.k3));
            println!("  K4:      {}", to_hex(keys.k4));
        }

        Cli::Cycle {
            issuer_key,
            url,
            version,
        } => {
            let issuer_key = parse_hex_16(&issuer_key)?;
            let mut transport = connect_transport()?;

            println!("═══ CYCLE: BURN ═══");
            burn::cmd_burn(&mut transport, &issuer_key, &url, version).await?;

            println!("\n═══ CYCLE: WIPE ═══");
            burn::cmd_wipe(&mut transport, &issuer_key, version).await?;

            println!("\n═══ CYCLE: RE-BURN ═══");
            burn::cmd_burn(&mut transport, &issuer_key, &url, version).await?;

            println!("\n🎉 Full cycle completed successfully!");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_hex_16, parse_hex_7};

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
