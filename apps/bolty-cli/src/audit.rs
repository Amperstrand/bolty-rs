//! Audit-logging transport wrapper.
//!
//! Wraps any `ntag424::Transport` implementation and logs every APDU
//! exchange to an audit file (default: `/tmp/bolty-audit.log`) for
//! safety forensics and debugging. This ensures we can always trace
//! exactly what was sent to the card and what it replied.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use bolty_core::provenance::KeyProvenance;
use bolty_ntag::{Response, Transport};

static AUDIT_LOG_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Set the audit log path. Called once at startup.
/// Defaults to `/tmp/bolty-audit.log` if never called.
#[allow(dead_code)]
pub fn set_audit_log_path(path: PathBuf) {
    if let Ok(mut guard) = AUDIT_LOG_PATH.write() {
        *guard = Some(path);
    }
}

fn audit_log_path() -> PathBuf {
    match AUDIT_LOG_PATH.read() {
        Ok(guard) => guard
            .clone()
            .unwrap_or_else(|| PathBuf::from("/tmp/bolty-audit.log")),
        Err(_) => PathBuf::from("/tmp/bolty-audit.log"),
    }
}

/// Test-only mutex serializing tests that share the mutable audit log path.
#[cfg(test)]
pub static AUDIT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn log_entry(entry: &str) {
    let path = audit_log_path();
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        let _ = writeln!(f, "{entry}");
        let _ = f.flush();
    }
}

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{secs}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn log_event_with_provenance(msg: &str, provenance: Option<KeyProvenance>) {
    let ts = timestamp();
    let full = match provenance {
        Some(p) => format!("[{ts}] EVENT  {msg} [provenance={}]", p.to_audit_tag()),
        None => format!("[{ts}] EVENT  {msg}"),
    };
    log_entry(&full);
}

/// Write a human-readable event annotation to the audit log.
/// Use this to mark key operations: "trying derived K0 v1", "burn: writing K2", etc.
pub fn log_event(msg: &str) {
    log_event_with_provenance(msg, None);
}

/// A transport wrapper that logs all APDU exchanges to an audit file.
pub struct LoggingTransport<T> {
    inner: T,
}

impl<T> LoggingTransport<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Consume the wrapper and return the inner transport.
    #[allow(dead_code)]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Transport> Transport for LoggingTransport<T>
where
    T::Error: std::error::Error + 'static,
{
    type Error = T::Error;
    type Data = T::Data;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Self::Data>, Self::Error> {
        let ts = timestamp();
        log_entry(&format!(
            "[{ts}] TX APDU len={} data={}",
            apdu.len(),
            hex(apdu)
        ));

        let result = self.inner.transmit(apdu).await;

        match &result {
            Ok(resp) => {
                let data_bytes = resp.data.as_ref();
                log_entry(&format!(
                    "[{ts}] RX OK   sw={:02X}{:02X} len={} data={}",
                    resp.sw1,
                    resp.sw2,
                    data_bytes.len(),
                    hex(data_bytes),
                ));
            }
            Err(e) => {
                log_entry(&format!("[{ts}] RX ERR  error={e:?}"));
            }
        }

        result
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        let ts = timestamp();
        log_entry(&format!("[{ts}] GET_UID"));

        let result = self.inner.get_uid().await;

        match &result {
            Ok(uid) => {
                log_entry(&format!("[{ts}] GET_UID OK   uid={}", hex(uid.as_ref()),));
            }
            Err(e) => {
                log_entry(&format!("[{ts}] GET_UID ERR  error={e:?}"));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolty_core::provenance::KeyProvenance;
    use std::io::Read;

    #[test]
    fn provenance_tag_emitted() {
        let _guard = AUDIT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let mut tmp_path = std::env::temp_dir();
        tmp_path.push(format!(
            "bolty-audit-test-{}-provenance_tag_emitted.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp_path);
        set_audit_log_path(tmp_path.clone());

        log_event_with_provenance(
            "burn: SUCCESS — K0 v1, K1-K4 installed",
            Some(KeyProvenance::DerivedIssuer { version: 1 }),
        );

        let mut content = String::new();
        std::fs::File::open(&tmp_path)
            .map(|mut f| f.read_to_string(&mut content))
            .ok();
        assert!(
            content.ends_with(" [provenance=DerivedIssuer(1)]\n"),
            "expected audit line to end with provenance tag, got: {content:?}"
        );

        let _ = std::fs::remove_file(&tmp_path);
        log_event_with_provenance("plain event", None);
        let mut content2 = String::new();
        std::fs::File::open(&tmp_path)
            .map(|mut f| f.read_to_string(&mut content2))
            .ok();
        assert!(
            !content2.contains("[provenance="),
            "expected no provenance tag for None, got: {content2:?}"
        );

        let _ = std::fs::remove_file(&tmp_path);
    }
}
