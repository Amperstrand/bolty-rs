use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bolty_ntag::{PiccData, SessionError};

const AUTH_RETRY_DELAYS: &[u64] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const CIRCUIT_BREAKER_THRESHOLD: u32 = 10;

static TOTAL_AUTH_FAILURES: AtomicU32 = AtomicU32::new(0);

pub(crate) fn record_auth_failure() {
    let count = TOTAL_AUTH_FAILURES.fetch_add(1, Ordering::SeqCst) + 1;
    if count == 3 {
        eprintln!("  ⚠️  {count} total auth failures in this session. TotFailCtr is accumulating.");
    }
    if count >= CIRCUIT_BREAKER_THRESHOLD {
        eprintln!("🛑 CIRCUIT BREAKER: {count} total auth failures. Aborting to protect the card.");
        eprintln!("   TotFailCtr permanently locks the key at 1000 failures. Each attempt adds 1.");
        eprintln!("   Recovery: use try-key to clear delay (rapid retry), then scan-keys.");
        std::process::exit(6);
    }
}

#[allow(dead_code)]
pub(crate) fn auth_failure_count() -> u32 {
    TOTAL_AUTH_FAILURES.load(Ordering::SeqCst)
}

/// Returns `true` when SDM has at least one active feature (PICC data or
/// file-read MAC).
///
/// After `wipe()`, `Sdm::disabled()` leaves a `Some(Sdm{...})` shell with
/// `picc_data == None` and `file_read == None`.  A structural `sdm.is_some()`
/// check would treat that as "SDM active" and mis-classify the card.
pub(crate) fn is_sdm_functionally_active(sdm: Option<&bolty_ntag::Sdm>) -> bool {
    sdm.is_some_and(|s| !matches!(s.picc_data(), PiccData::None) || s.file_read().is_some())
}

pub(crate) use bolty_ntag::{NdefUri, parse_ndef_uri, uid_to_fixed};

pub(crate) fn is_auth_delay<T: std::error::Error + std::fmt::Debug>(err: &SessionError<T>) -> bool {
    matches!(
        err,
        SessionError::ErrorResponse(bolty_ntag::ResponseStatus::AuthenticationDelay)
    )
}

pub(crate) fn gen_rnd_a() -> anyhow::Result<[u8; 16]> {
    let mut rnd_a = [0u8; 16];
    getrandom::fill(&mut rnd_a).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    Ok(rnd_a)
}

pub(crate) struct AuthRetry {
    attempt: usize,
}

impl AuthRetry {
    pub(crate) fn new() -> Self {
        Self { attempt: 0 }
    }

    pub(crate) fn next_delay(&mut self) -> Option<Duration> {
        let delay_secs = *AUTH_RETRY_DELAYS.get(self.attempt)?;
        self.attempt += 1;
        let total = 1 + AUTH_RETRY_DELAYS.len();
        println!(
            "  Auth delay — waiting {delay_secs}s (retry {}/{total})...",
            self.attempt
        );
        Some(Duration::from_secs(delay_secs))
    }

    pub(crate) fn exhausted_msg() -> String {
        format!(
            "authentication failed after {} attempts — auth delay persists.\n\
             The NTAG424 datasheet says 'keep trying until full delay is spent'.\n\
             This means sending AuthFirst repeatedly within the SAME connection.\n\
             If this fails, the card may need a different key — use scan-keys.",
            1 + AUTH_RETRY_DELAYS.len()
        )
    }
}

impl Default for AuthRetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a `bolty_ntag::Error` to a user-friendly `anyhow::Error` message.
///
/// Used by burn.rs and wipe.rs to translate library errors into actionable
/// CLI messages with recovery instructions.
pub(crate) fn map_ntag_error<T>(e: bolty_ntag::Error<T>) -> anyhow::Error
where
    T: std::error::Error + Send + Sync + 'static,
{
    match e {
        bolty_ntag::Error::AuthenticationDelay => {
            anyhow::anyhow!(
                "authentication delay (91AD) — too many consecutive failures.\n\
                 Recovery: the NTAG424 datasheet says 'keep trying until full delay\n\
                 is spent'. Retry AuthFirst rapidly within the same PCSC connection.\n\
                 Do NOT create new connections between retries."
            )
        }
        bolty_ntag::Error::WrongCardType { vendor, card_type } => anyhow::anyhow!(
            "Card is not NTAG424 DNA (vendor=0x{vendor:02X}, type=0x{card_type:02X})"
        ),
        bolty_ntag::Error::NdefVerificationFailed { written, read_back } => anyhow::anyhow!(
            "NDEF verification failed: wrote {written} bytes, read back {read_back}.\n\
             Recovery: the card may be in a partially-written state. Re-run the operation."
        ),
        bolty_ntag::Error::KeyVersionMismatch {
            key_number,
            expected,
            actual,
        } => anyhow::anyhow!(
            "Key {key_number} version mismatch: expected {expected:#04X}, got {actual:#04X}.\n\
             Recovery: re-run the operation to overwrite the mismatched key."
        ),
        bolty_ntag::Error::SdmVerificationFailed => {
            anyhow::anyhow!("SDM verification failed.\nRecovery: re-run the operation.")
        }
        bolty_ntag::Error::SdmUrl(e) => anyhow::anyhow!("SDM URL config error: {e}"),
        bolty_ntag::Error::Session(e) => anyhow::anyhow!("operation failed: {e}"),
        bolty_ntag::Error::Transport(e) => anyhow::anyhow!("transport error: {e}"),
    }
}
