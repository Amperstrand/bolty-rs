//! Audit-logging transport wrapper.
//!
//! Wraps any `ntag424::Transport` implementation and logs every APDU
//! exchange to an audit file (default: `/tmp/bolty-audit.log`) for
//! safety forensics and debugging. This ensures we can always trace
//! exactly what was sent to the card and what it replied.
//!
//! Line-format contract: every entry this module writes starts with
//! `[<epoch-ms>] `. The shared file is multi-writer and historical
//! copies contain OUT-OF-BAND prose (reader tables, labgrid dumps
//! appended by lane scripts) and glued same-line entries from
//! unsynchronized parallel writers (issue #256). Readers must tolerate
//! both — on the host side `tools/hil/hil/audit_log.py` is the
//! tolerant parser.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bolty_core::provenance::KeyProvenance;
use bolty_ntag::{Response, Transport};

static AUDIT_LOG_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Issue #210: process-start wall clock, captured once. Every banner and
/// clock-step note is judged against this, so a mid-process NTP step or a
/// container re-entry with a skewed clock becomes visible in the log
/// instead of silently interleaving wrong timestamps with other lanes'.
static PROCESS_START_MS: LazyLock<u128> = LazyLock::new(now_epoch_ms);

/// The session banner fires on the FIRST audit write of the process.
static BANNER_WRITTEN: AtomicBool = AtomicBool::new(false);

/// One CLOCK_STEP_BACKWARD note per process (flag, not per-entry spam).
static CLOCK_STEP_NOTED: AtomicBool = AtomicBool::new(false);

/// Issue #210 (review follow-up): the last timestamp THIS process stamped
/// (0 = none yet). Mid-process backward steps that remain above process
/// start are only visible against this, not against PROCESS_START_MS.
static LAST_STAMP_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Test hook: when non-zero, [`now_epoch_ms`] reports this instead of the
/// real clock (issue #210 tests simulate backward clock steps).
#[cfg(test)]
use std::sync::atomic::AtomicU64;
#[cfg(test)]
static CLOCK_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

fn now_epoch_ms() -> u128 {
    #[cfg(test)]
    {
        let o = CLOCK_OVERRIDE_MS.load(Ordering::Relaxed);
        if o != 0 {
            return u128::from(o);
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

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
pub static AUDIT_TEST_MUTEX: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Reset the audit log path to None. Call this in test cleanup to prevent
/// test-to-test path leakage when tests run in parallel.
#[cfg(test)]
pub fn reset_audit_log_path_for_test() {
    if let Ok(mut guard) = AUDIT_LOG_PATH.write() {
        *guard = None;
    }
}

/// Test-only: re-arm the one-shot session banner and clear the clock-step
/// flag (issue #210 tests exercise the banner repeatedly in one process).
#[cfg(test)]
pub fn reset_banner_for_test() {
    BANNER_WRITTEN.store(false, Ordering::Relaxed);
    CLOCK_STEP_NOTED.store(false, Ordering::Relaxed);
}

/// RFC 3339 UTC from epoch millis, dependency-free (civil-from-days per
/// Howard Hinnant's algorithm — the crate pins deps tightly, so no chrono).
fn wall_utc(epoch_ms: u128) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let ms = (epoch_ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // civil_from_days (era shift to 1970-03-01-based months)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_ascii_lowercase())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

fn exe_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown-exe".into())
}

/// Parse a leading `[<millis>]` timestamp from the last line of an
/// existing audit log, if any (for future-dated-entry detection).
fn last_line_epoch_ms(path: &std::path::Path) -> Option<u128> {
    let f = std::fs::File::open(path).ok()?;
    let reader = BufReader::new(f);
    let mut last: Option<u128> = None;
    for line in reader.lines().map_while(Result::ok) {
        if let Some(v) = line
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
            .and_then(|(ts, _)| ts.parse::<u128>().ok())
        {
            last = Some(v);
        }
    }
    last
}

/// Issue #210: session banner on the process's first audit write. Names the
/// writer (pid/host/exe), stamps a human-readable wall clock next to the
/// epoch millis, and flags future-dated entries left by other (skewed)
/// writers so cross-lane slices stay attributable even with skew.
fn write_session_banner(path: &std::path::Path) {
    if BANNER_WRITTEN.swap(true, Ordering::Relaxed) {
        return;
    }
    let now = now_epoch_ms();
    let mut line = format!(
        "[{now}] SESSION START pid={} host={} exe={} wall={}",
        std::process::id(),
        hostname(),
        exe_name(),
        wall_utc(now),
    );
    if let Some(last) = last_line_epoch_ms(path) {
        // Entries in the future relative to OUR clock => another writer's
        // clock is skewed (container/toolbox). Flag, don't reject: the log
        // is shared and we don't own foreign lanes' entries.
        if last > now + 1000 {
            let delta = last - now;
            line.push_str(&format!(" prior_future_delta_ms={delta}"));
        }
    }
    write_raw(path, &line);
}

fn write_raw(path: &std::path::Path, entry: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    {
        let _ = writeln!(f, "{entry}");
        let _ = f.flush();
    }
}

fn log_entry(entry: &str) {
    let path = audit_log_path();
    write_session_banner(&path);
    write_raw(&path, entry);
}

fn timestamp() -> String {
    let now = now_epoch_ms();
    // Issue #210: a backward clock step mid-process (NTP correction, host
    // resync) would interleave pre-step and post-step timestamps from THIS
    // pid with no marker. Note it once, loudly. The reference is the
    // HIGHER of process start and our own last stamp, so both a step below
    // process start and an ordinary mid-process correction (still above
    // start) are caught.
    let prev = LAST_STAMP_MS.load(Ordering::Relaxed);
    let reference = if prev != 0 {
        std::cmp::max(u128::from(prev), *PROCESS_START_MS)
    } else {
        *PROCESS_START_MS
    };
    if now + 1000 < reference && !CLOCK_STEP_NOTED.swap(true, Ordering::Relaxed) {
        let path = audit_log_path();
        write_session_banner(&path);
        write_raw(
            &path,
            &format!(
                "[{now}] EVENT  CLOCK_STEP_BACKWARD delta_ms={} \
                 (reference point {}; entries above/below may straddle the step)",
                reference - now,
                reference,
            ),
        );
    }
    LAST_STAMP_MS.store(u64::try_from(now).unwrap_or(u64::MAX), Ordering::Relaxed);
    format!("{now}")
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
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();

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
        reset_audit_log_path_for_test();
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
    use super::{
        AUDIT_TEST_MUTEX, log_event, log_event_with_provenance, reset_audit_log_path_for_test,
        set_audit_log_path,
    };
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
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
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
        reset_audit_log_path_for_test();
    }

    #[test]
    fn provenance_tag_is_appended_at_end_of_line() {
        // SECURITY invariant: the provenance tag must be the LAST token of the
        // line. If it were inserted into the middle of `msg`, a malformed
        // message containing `]` or `[provenance=` could break parser
        // field-splitting or spoof a tag. Appending makes the tag unforgeable
        // from the message body.
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
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
        reset_audit_log_path_for_test();
    }

    #[test]
    fn none_provenance_emits_no_tag_token() {
        // SECURITY invariant: `None` provenance must NOT emit a `[provenance=]`
        // token at all. A spurious empty tag would confuse parsers that key on
        // tag presence to decide whether a line is a key-operation event.
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
        let path = fresh_path("none");
        set_audit_log_path(path.clone());

        log_event_with_provenance("plain event", None);

        let line = read_audit(&path);
        assert!(
            !line.contains("[provenance="),
            "None provenance must not emit a tag token, got: {line:?}"
        );

        let _ = std::fs::remove_file(&path);
        reset_audit_log_path_for_test();
    }

    #[test]
    fn factory_default_tag_renders_verbatim_in_log() {
        // SECURITY invariant: the factory-default path must label the line
        // `[provenance=FactoryDefault]` exactly, so an auditor grepping for
        // blank-card burns matches reliably.
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
        let path = fresh_path("factory");
        set_audit_log_path(path.clone());

        log_event_with_provenance("burn", Some(KeyProvenance::FactoryDefault));

        let line = read_audit(&path);
        assert!(line.contains("[provenance=FactoryDefault]"));

        let _ = std::fs::remove_file(&path);
        reset_audit_log_path_for_test();
    }

    #[test]
    fn message_body_cannot_spoof_provenance_tag() {
        // SECURITY invariant: because the real tag is always appended LAST, a
        // malicious message that itself contains `[provenance=UnknownExternal]`
        // must not be able to overwrite or mask the genuine trailing tag. The
        // parser reads the final `[provenance=...]` token, which is the real
        // one.
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
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
        reset_audit_log_path_for_test();
    }
}

/// Issue #210 suite: session banners + clock-sanity notes keep the shared
/// audit log attributable across processes/lanes even when a writer's
/// clock is skewed (containers, toolboxes, NTP steps).
#[cfg(test)]
mod issue210_tests {
    use super::{
        AUDIT_TEST_MUTEX, CLOCK_OVERRIDE_MS, CLOCK_STEP_NOTED, LAST_STAMP_MS, PROCESS_START_MS,
        log_event, reset_audit_log_path_for_test, reset_banner_for_test, set_audit_log_path,
        wall_utc,
    };
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    fn fresh_path(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bolty-issue210-audit-{label}-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn read_audit(path: &std::path::Path) -> String {
        let mut s = String::new();
        std::fs::File::open(path)
            .map(|mut f| f.read_to_string(&mut s))
            .ok();
        s
    }

    #[test]
    fn session_banner_identifies_writer_exactly_once() {
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
        let path = fresh_path("banner");
        set_audit_log_path(path.clone());
        reset_banner_for_test();

        log_event("first entry");
        log_event("second entry");

        let content = read_audit(&path);
        let banners = content
            .lines()
            .filter(|l| l.contains("SESSION START"))
            .count();
        assert_eq!(
            banners, 1,
            "exactly one banner per process, got: {content:?}"
        );
        let banner = content
            .lines()
            .find(|l| l.contains("SESSION START"))
            .expect("banner present");
        assert!(
            banner.contains("wall="),
            "banner carries wall clock: {banner:?}"
        );
        // Structural wall-clock check: wall=YYYY-MM-DDTHH:MM:SS.mmmZ.
        let wall = banner
            .split("wall=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_default();
        let structural = wall.len() == 24
            && wall.bytes().next().is_some_and(|b| b.is_ascii_digit())
            && wall.bytes().take(4).all(|b| b.is_ascii_digit())
            && wall.get(4..5).is_some_and(|d| d == "-")
            && wall.get(10..11).is_some_and(|d| d == "T")
            && wall.ends_with('Z');
        assert!(structural, "wall clock must be RFC3339 UTC, got: {wall:?}");
        assert!(banner.contains(&format!("pid={}", std::process::id())));
        assert!(banner.contains("host="));
        assert!(banner.contains("exe="));

        let _ = std::fs::remove_file(&path);
        reset_audit_log_path_for_test();
    }

    #[test]
    fn banner_flags_future_dated_entries_from_skewed_writers() {
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
        let path = fresh_path("future");
        // Pre-seed the shared log with a future-dated entry as a skewed
        // foreign lane would leave it (1 hour ahead of us).
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() + 3_600_000)
            .unwrap_or(0);
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "[{future}] EVENT  foreign-lane entry (skewed clock)").unwrap();
        }
        set_audit_log_path(path.clone());
        reset_banner_for_test();

        log_event("our entry");

        let content = read_audit(&path);
        assert!(
            content.contains("prior_future_delta_ms="),
            "banner must flag the future-dated prior entry: {content:?}"
        );

        let _ = std::fs::remove_file(&path);
        reset_audit_log_path_for_test();
    }

    #[test]
    fn backward_clock_step_emits_a_marker_once() {
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
        let path = fresh_path("clockstep");
        set_audit_log_path(path.clone());
        reset_banner_for_test();
        CLOCK_STEP_NOTED.store(false, Ordering::Relaxed);
        LAST_STAMP_MS.store(0, Ordering::Relaxed);

        // Simulate the host clock stepping 5000 ms behind process start.
        let stepped = u64::try_from(*PROCESS_START_MS)
            .unwrap_or(0)
            .saturating_sub(5000);
        CLOCK_OVERRIDE_MS.store(stepped, Ordering::Relaxed);
        log_event("entry under stepped clock");
        CLOCK_OVERRIDE_MS.store(0, Ordering::Relaxed);

        let content = read_audit(&path);
        assert!(
            content.contains("CLOCK_STEP_BACKWARD"),
            "a backward step must be flagged: {content:?}"
        );
        let marks = content
            .lines()
            .filter(|l| l.contains("CLOCK_STEP_BACKWARD"))
            .count();
        assert_eq!(marks, 1, "flag fires exactly once: {content:?}");

        let _ = std::fs::remove_file(&path);
        CLOCK_STEP_NOTED.store(false, Ordering::Relaxed);
        LAST_STAMP_MS.store(0, Ordering::Relaxed);
        reset_audit_log_path_for_test();
    }

    #[test]
    fn midprocess_backward_step_above_start_still_flags() {
        // Review follow-up: a correction that stays LATER than process
        // start must also be flagged (the old process-start-only check
        // missed ordinary mid-process NTP corrections).
        let _guard = AUDIT_TEST_MUTEX.blocking_lock();
        let path = fresh_path("clockstep2");
        set_audit_log_path(path.clone());
        reset_banner_for_test();
        CLOCK_STEP_NOTED.store(false, Ordering::Relaxed);
        LAST_STAMP_MS.store(0, Ordering::Relaxed);

        let ps = u64::try_from(*PROCESS_START_MS).unwrap_or(0);
        // First stamp: one minute into the process (above start).
        CLOCK_OVERRIDE_MS.store(ps + 60_000, Ordering::Relaxed);
        log_event("entry one minute into the process");
        // Then a 5 s backward correction, still above process start.
        CLOCK_OVERRIDE_MS.store(ps + 55_000, Ordering::Relaxed);
        log_event("entry after mid-process correction");
        CLOCK_OVERRIDE_MS.store(0, Ordering::Relaxed);

        let content = read_audit(&path);
        assert!(
            content.contains("CLOCK_STEP_BACKWARD"),
            "mid-process step above start must be flagged: {content:?}"
        );
        let marks = content
            .lines()
            .filter(|l| l.contains("CLOCK_STEP_BACKWARD"))
            .count();
        assert_eq!(marks, 1, "flag fires exactly once: {content:?}");
        assert!(
            content.contains("delta_ms=5000"),
            "delta must reference the previous stamp: {content:?}"
        );

        let _ = std::fs::remove_file(&path);
        CLOCK_STEP_NOTED.store(false, Ordering::Relaxed);
        LAST_STAMP_MS.store(0, Ordering::Relaxed);
        reset_audit_log_path_for_test();
    }

    #[test]
    fn wall_utc_matches_known_instants() {
        assert_eq!(wall_utc(0), "1970-01-01T00:00:00.000Z");
        // 2026-10-29T12:00:00.000Z (computed independently of this code)
        assert_eq!(wall_utc(1_793_275_200_000), "2026-10-29T12:00:00.000Z");
        // 2027-01-15T08:00:00.500Z — leap-year era boundary sanity
        assert_eq!(wall_utc(1_800_000_000_500), "2027-01-15T08:00:00.500Z");
    }
}
