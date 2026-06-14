//! Audit-logging transport wrapper.
//!
//! Wraps any `ntag424::Transport` implementation and logs every APDU
//! exchange to an audit file (default: `/tmp/bolty-audit.log`) for
//! safety forensics and debugging. This ensures we can always trace
//! exactly what was sent to the card and what it replied.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use ntag424::{Response, Transport};

static AUDIT_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Set the audit log path. Called once at startup.
/// Defaults to `/tmp/bolty-audit.log` if never called.
#[allow(dead_code)]
pub fn set_audit_log_path(path: PathBuf) {
    let _ = AUDIT_LOG_PATH.set(path);
}

fn audit_log_path() -> &'static PathBuf {
    AUDIT_LOG_PATH.get_or_init(|| PathBuf::from("/tmp/bolty-audit.log"))
}

fn log_entry(entry: &str) {
    let path = audit_log_path();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
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
