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

/// SECURITY regression suite for the audit layer (issue #41).
///
/// The integration test in `tests/security/` cannot import this binary crate's
/// private modules, so the audit-specific invariants live here. These tests
/// pin the audit-line *structure* that downstream forensic parsers rely on:
/// the timestamp leads, the provenance tag trails, and `None` omits the tag.
#[cfg(test)]
mod security_tests {
    use super::{AUDIT_TEST_MUTEX, log_event, log_event_with_provenance, set_audit_log_path};
    use bolty_core::provenance::KeyProvenance;
    use std::io::Read;

    /// Read the full contents of the current audit log path, or empty string.
    fn read_audit(path: &std::path::Path) -> String {
        let mut s = String::new();
        std::fs::File::open(path)
            .map(|mut f| f.read_to_string(&mut s))
            .ok();
        s
    }

    /// Allocate a per-test temp audit path so parallel tests never collide.
    fn fresh_path(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bolty-security-audit-{}-{label}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn audit_line_starts_with_bracketed_timestamp() {
        // SECURITY invariant: every audit line must lead with `[<millis>]` so a
        // SIEM parser can extract the timestamp with a fixed anchor. A line
        // without the leading bracket would break timestamp extraction.
        let _guard = AUDIT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = fresh_path("timestamp");
        set_audit_log_path(path.clone());

        log_event("security-suite probe");

        let line = read_audit(&path);
        assert!(
            line.starts_with('['),
            "audit line must start with '[' (timestamp), got: {line:?}"
        );
        // Parse the leading `[<millis>]` without string-slicing (clippy:
        // string_slice). strip_prefix + split_once avoid index arithmetic.
        let after_open = line
            .strip_prefix('[')
            .expect("checked starts_with('[') above");
        let (ts_str, _rest) = after_open
            .split_once(']')
            .expect("timestamp bracket must close");
        let ts: u128 = ts_str
            .parse()
            .expect("timestamp must be numeric epoch millis");
        assert!(ts > 0, "timestamp must be non-zero epoch millis");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn provenance_tag_is_appended_at_end_of_line() {
        // SECURITY invariant: the provenance tag must be the LAST token of the
        // line. If it were inserted into the middle of `msg`, a malformed
        // message containing `]` or `[provenance=` could break parser
        // field-splitting or spoof a tag. Appending makes the tag unforgeable
        // from the message body.
        let _guard = AUDIT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = fresh_path("appended");
        set_audit_log_path(path.clone());

        log_event_with_provenance(
            "msg with [brackets] and = signs inside",
            Some(KeyProvenance::DerivedIssuer { version: 2 }),
        );

        let line = read_audit(&path);
        assert!(
            line.trim_end().ends_with("[provenance=DerivedIssuer(2)]"),
            "provenance tag must be the trailing token, got: {line:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn none_provenance_emits_no_tag_token() {
        // SECURITY invariant: `None` provenance must NOT emit a `[provenance=]`
        // token at all. A spurious empty tag would confuse parsers that key on
        // tag presence to decide whether a line is a key-operation event.
        let _guard = AUDIT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = fresh_path("none");
        set_audit_log_path(path.clone());

        log_event_with_provenance("plain event", None);

        let line = read_audit(&path);
        assert!(
            !line.contains("[provenance="),
            "None provenance must not emit a tag token, got: {line:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn factory_default_tag_renders_verbatim_in_log() {
        // SECURITY invariant: the factory-default path must label the line
        // `[provenance=FactoryDefault]` exactly, so an auditor grepping for
        // blank-card burns matches reliably.
        let _guard = AUDIT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = fresh_path("factory");
        set_audit_log_path(path.clone());

        log_event_with_provenance("burn", Some(KeyProvenance::FactoryDefault));

        let line = read_audit(&path);
        assert!(line.contains("[provenance=FactoryDefault]"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn message_body_cannot_spoof_provenance_tag() {
        // SECURITY invariant: because the real tag is always appended LAST, a
        // malicious message that itself contains `[provenance=UnknownExternal]`
        // must not be able to overwrite or mask the genuine trailing tag. The
        // parser reads the final `[provenance=...]` token, which is the real
        // one.
        let _guard = AUDIT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = fresh_path("spoof");
        set_audit_log_path(path.clone());

        log_event_with_provenance(
            "evil [provenance=UnknownExternal] inject",
            Some(KeyProvenance::FactoryDefault),
        );

        let line = read_audit(&path);
        // The line must end with the GENUINE tag, not the injected one.
        assert!(
            line.trim_end().ends_with("[provenance=FactoryDefault]"),
            "trailing provenance tag must be the genuine one, got: {line:?}"
        );

        let _ = std::fs::remove_file(&path);
    }
}
