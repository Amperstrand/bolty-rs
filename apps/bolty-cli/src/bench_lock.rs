//! Cross-project bench flock for physical-reader CLI runs (#209).
//!
//! pcscd gates nothing: while a lane holds the labgrid place, a BARE
//! `bolty-cli` can still drive the same reader (demonstrated 2026-10-19:
//! try-key/wipe on the then-read-only card while the H1 lane held
//! ref-acr1252). This is the CLI-side twin of the tollgate-lab BenchLock:
//! connecting to a PHYSICAL reader takes the same well-known advisory
//! flock (`/tmp/amperstrand-bench.lock`) with a loud, holder-named error
//! when another session holds it.
//!
//! Interop contract (matches tollgate_lab.hardware.bench_lock):
//! - exclusive flock, non-blocking, holder info written as `key: value`
//!   lines (readable by `read_bench_lock` on the Python side);
//! - lock-holding harnesses that shell out to bolty-cli MUST pass
//!   `BOLTY_SKIP_BENCH_LOCK=1` to the child — the parent's flock already
//!   provides exclusivity, and flock is per-open-file-description, so the
//!   child would otherwise block against its own parent;
//! - virtual readers (vpcd/vPICC) never take the lock: they share no
//!   physical antenna.

use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

/// Same well-known path as tollgate-lab's BenchLock (name
/// "amperstrand-bench"): one lock, every language.
pub const BENCH_LOCK_PATH: &str = "/tmp/amperstrand-bench.lock";

/// Opt-out for lock-holding harness children and CI (see module docs).
pub const SKIP_ENV: &str = "BOLTY_SKIP_BENCH_LOCK";

/// Held lock guard — releases on drop (OwnedFd close drops the flock).
pub struct BenchLockGuard {
    _fd: Option<OwnedFd>,
}

impl BenchLockGuard {
    /// An inactive guard (env opt-out or virtual reader).
    pub fn inactive() -> Self {
        Self { _fd: None }
    }

    #[allow(dead_code)] // diagnostics hook for future assert-helpers
    pub fn is_held(&self) -> bool {
        self._fd.is_some()
    }
}

/// Why the lock could not be taken: the current holder's recorded info
/// (advisory text — the flock itself is the truth).
#[derive(Debug)]
pub struct BenchLockHeld {
    pub holder: String,
    pub path: &'static str,
}

impl std::fmt::Display for BenchLockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "bench lock {} is held by another session:\n{}\n\
             pcscd gates nothing (#209): a bare CLI must not race other \
             lanes on physical readers. Take the labgrid place / bench \
             lock first, or wait for the holder. Override (harness \
             children whose parent already holds the lock, CI, virtual \
             readers): {}=1",
            self.path, self.holder, SKIP_ENV
        )
    }
}

fn flock_ex_nb(fd: std::os::unix::io::BorrowedFd<'_>) -> std::io::Result<bool> {
    // SAFETY: libc flock(2) on a valid fd; returns 0 on success.
    let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EWOULDBLOCK) => Ok(false),
        _ => Err(err),
    }
}

/// Holder info for OUR acquisition — the `key: value` shape the Python
/// side's `read_bench_lock` prints, so `labgrid-client who`-style
/// debugging reads the same from either language.
pub fn holder_text(reason: &str) -> String {
    let pid = std::process::id();
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut s = format!("session: bolty-cli\npid: {pid}\nproject: bolty-rs");
    if !reason.is_empty() {
        s.push_str("\ncmd: ");
        s.push_str(reason);
    }
    s.push_str(&format!("\nsince: unix+{since}"));
    s
}

/// Read the current holder info (best effort — advisory text).
fn read_holder(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Take the bench lock for a physical-reader run. `Err` is a LOUD,
/// holder-named refusal — the caller must not touch the reader.
pub fn acquire(reason: &str) -> Result<BenchLockGuard, BenchLockHeld> {
    if std::env::var_os(SKIP_ENV).is_some() {
        return Ok(BenchLockGuard::inactive());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o666)
        .open(BENCH_LOCK_PATH);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            // Cannot even open the lock file: fail CLOSED (advisory lock
            // we cannot take is a lock we cannot honor).
            return Err(BenchLockHeld {
                holder: format!("(lock file unopenable: {e})"),
                path: BENCH_LOCK_PATH,
            });
        }
    };
    match flock_ex_nb(file.as_fd()) {
        Ok(true) => {
            let _ = file.set_len(0);
            let _ = file.seek(std::io::SeekFrom::Start(0));
            let _ = file.write_all(holder_text(reason).as_bytes());
            let _ = file.flush();
            Ok(BenchLockGuard {
                _fd: Some(file.into()),
            })
        }
        Ok(false) => Err(BenchLockHeld {
            holder: read_holder(BENCH_LOCK_PATH),
            path: BENCH_LOCK_PATH,
        }),
        Err(e) => Err(BenchLockHeld {
            holder: format!("(flock failed: {e})"),
            path: BENCH_LOCK_PATH,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn test_path(tag: &str) -> String {
        format!(
            "/tmp/bolty-bench-lock-test-{tag}-{}.lock",
            std::process::id()
        )
    }

    #[test]
    fn holder_text_is_python_read_bench_lock_shaped() {
        let t = holder_text("try-key");
        assert!(t.starts_with("session: bolty-cli\n"));
        assert!(t.contains("pid: "));
        assert!(t.contains("project: bolty-rs"));
        assert!(t.contains("cmd: try-key"));
        assert!(t.contains("since: unix+"));
    }

    #[test]
    fn acquire_and_hold_then_block_second_taker() {
        let path = test_path("hold");
        let _ = std::fs::remove_file(&path);
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        assert!(flock_ex_nb(first.as_fd()).unwrap(), "first flock must win");
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        assert!(
            !flock_ex_nb(second.as_fd()).unwrap(),
            "second EX|NB taker must be told the lock is held"
        );
        // and the raw fd is flock-able at all (sanity for the libc call)
        assert!(second.as_raw_fd() >= 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn guard_drop_releases_the_lock() {
        let path = test_path("drop");
        let _ = std::fs::remove_file(&path);
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .unwrap();
            assert!(flock_ex_nb(file.as_fd()).unwrap());
            let _guard = BenchLockGuard {
                _fd: Some(file.into()),
            };
            // guard alive here; dropped at block end
        }
        let recheck = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        assert!(
            flock_ex_nb(recheck.as_fd()).unwrap(),
            "dropping the guard must release the flock"
        );
        let _ = std::fs::remove_file(&path);
    }
}
