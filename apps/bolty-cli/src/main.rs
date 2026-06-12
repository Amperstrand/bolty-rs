mod burn;
mod transport;

use bolty_core::derivation::BoltcardDeterministicDeriver;
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
    let trimmed = s.trim();
    if trimmed.len() != 32 {
        anyhow::bail!("expected 16 bytes (32 hex chars), got {} chars", trimmed.len());
    }
    let bytes = hex::decode(trimmed)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("invalid 16-byte hex"))
}

fn parse_hex_7(s: &str) -> anyhow::Result<[u8; 7]> {
    let trimmed = s.trim();
    if trimmed.len() != 14 {
        anyhow::bail!("expected 7 bytes (14 hex chars), got {} chars", trimmed.len());
    }
    let bytes = hex::decode(trimmed)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("invalid 7-byte hex"))
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
            println!("  cardKey: {}", hex::encode(keys.card_key));
            println!("  K0:      {}", hex::encode(keys.k0));
            println!("  K1:      {}", hex::encode(keys.k1));
            println!("  K2:      {}", hex::encode(keys.k2));
            println!("  K3:      {}", hex::encode(keys.k3));
            println!("  K4:      {}", hex::encode(keys.k4));
        }
    }

    Ok(())
}
