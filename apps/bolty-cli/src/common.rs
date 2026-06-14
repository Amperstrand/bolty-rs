use ntag424::{SessionError, Uid};

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
