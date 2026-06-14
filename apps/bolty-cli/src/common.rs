use std::time::Duration;

use ntag424::{Session, SessionError, Transport, Uid};

const AUTH_RETRY_DELAYS: &[u64] = &[2, 5];

pub(crate) fn uid_to_fixed(uid: &Uid) -> [u8; 7] {
    match uid {
        Uid::Fixed(f) => *f,
        Uid::Random(_) => [0u8; 7],
    }
}

pub(crate) fn is_auth_delay<T: std::error::Error + std::fmt::Debug>(err: &SessionError<T>) -> bool {
    matches!(
        err,
        SessionError::ErrorResponse(ntag424::types::ResponseStatus::AuthenticationDelay)
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
            "authentication failed after {} attempts — auth delay persisted. \
             Wait 30s for the card to reset, then retry.",
            1 + AUTH_RETRY_DELAYS.len()
        )
    }
}

impl Default for AuthRetry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) async fn preflight_check<T: Transport>(transport: &mut T) -> anyhow::Result<[u8; 7]>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let session = Session::default();

    let uid = session
        .get_selected_uid(transport)
        .await
        .map_err(|e| anyhow::anyhow!("pre-flight: card not responding ({e})"))?;
    let uid_fixed = uid_to_fixed(&uid);

    let version = session
        .get_version(transport)
        .await
        .map_err(|e| anyhow::anyhow!("pre-flight: cannot read card version ({e})"))?;

    if version.hw_vendor_id() != 0x04 || version.hw_type() != 0x04 {
        anyhow::bail!(
            "pre-flight: card is not NTAG424 DNA (vendor={:02X}, type={:02X}). \
             Refusing to modify non-NTAG424 card.",
            version.hw_vendor_id(),
            version.hw_type()
        );
    }

    Ok(uid_fixed)
}
