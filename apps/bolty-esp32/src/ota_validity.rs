//! Serve-proven OTA rollback validity gate (ccid-firmware-rs #494 audit
//! adoption, item M; port of ccid #294 WS2 `ccid_service::ota_validity`).
//!
//! ESP-IDF app-rollback semantics: with
//! `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` compiled into the bootloader
//! (sdkconfig.defaults / sdkconfig.defaults.nucula — takes effect at the
//! next flash, see the caveat there), a freshly booted OTA image runs in
//! the `ESP_OTA_IMG_PENDING_VERIFY` state and reverts to the previous
//! slot on the next reset unless the app calls
//! `esp_ota_mark_app_valid_cancel_rollback()`. The image gets exactly
//! ONE boot to prove itself — no timeout, no watchdog involvement, any
//! reset before confirmation reverts.
//!
//! The proof bolty demands is **serve evidence**, never "reached
//! app_main": the first SUCCESSFUL product exchange —
//!
//! * a card transaction completed with `WorkflowResult::Success`
//!   (`workflow::dispatch_command` fires on burn/wipe/inspect/keyver/
//!   check — the shared choke point for console, REST and job-runner
//!   card paths),
//! * a 2xx REST API response (`rest::respond_json`),
//! * a successful nucula console card op (poll/uid/inspect in
//!   `firmware_nucula.rs`).
//!
//! Boundary: the gate itself cannot call ESP-IDF, so the platform
//! mark-valid fn is INSTALLED by the firmware mains via
//! [`arm_platform()`] before serving. Unarmed = inert: host tests,
//! non-OTA builds. A pending-verify image that never completes one
//! successful exchange still reverts — that is the defense working, not
//! a regression.

use std::sync::Mutex;

/// The one-boot state machine, struct-ified (ccid's `#350` pattern) so
/// the semantics are unit-testable without process-global state. The
/// live gate is [`GATE`] below.
#[derive(Debug, Default)]
pub struct ValidityGate {
    /// The platform mark-valid call, installed by the firmware main.
    marker: Option<fn() -> i32>,
    /// Set once the first serve evidence ran the marker — every later
    /// exchange is a plain load; the marker runs at most once per boot
    /// by construction.
    marked: bool,
}

impl ValidityGate {
    pub const fn new() -> Self {
        Self {
            marker: None,
            marked: false,
        }
    }

    /// Whether a marker is installed (diagnostic/test surface).
    pub fn armed(&self) -> bool {
        self.marker.is_some()
    }

    /// Install the platform mark-valid call. Returns `false` when the
    /// gate already ran a marker this boot (late arming after the first
    /// evidence is a no-op — evidence observed while disarmed does not
    /// latch).
    pub fn arm(&mut self, marker: fn() -> i32) -> bool {
        if self.marked {
            return false;
        }
        self.marker = Some(marker);
        true
    }

    /// Serve evidence, fired by the product paths on every completed
    /// successful exchange. The FIRST evidence (while armed) runs the
    /// installed marker exactly once and logs the platform rc (0 =
    /// marked valid; nonzero = not pending-verify — first boot, factory
    /// slot, or a bootloader without the rollback state machine —
    /// logged, never fatal). Every later signal is a no-op. Returns
    /// `true` when THIS call ran the marker. `source` names the evidence
    /// site for the log line (e.g. `"card-burn"`, `"rest-2xx"`).
    pub fn note_serve_evidence(&mut self, source: &str) -> bool {
        let Some(marker) = self.marker else {
            // Unarmed: host tests, non-OTA builds. Debug, not warn:
            // every unarmed exchange passes here.
            log::debug!("ota-validity: serve evidence ({source}) — gate not armed");
            return false;
        };
        if self.marked {
            return false;
        }
        self.marked = true;
        let rc = marker();
        if rc == 0 {
            log::info!("ota-validity: first serve evidence ({source}) — image marked valid");
        } else {
            log::warn!(
                "ota-validity: first serve evidence ({source}) — mark rc={rc} \
                 (not pending-verify: first boot, factory slot, or rollback disabled)"
            );
        }
        true
    }
}

/// The live, process-global gate. Mutex only because a static must be
/// `Sync`; contention is nil — one lock per served exchange after the
/// first.
static GATE: Mutex<ValidityGate> = Mutex::new(ValidityGate::new());

/// Arm the gate from an OTA-capable main BEFORE serving: install the
/// platform mark-valid call. `marker` must be thread-safe (it runs on
/// whichever task first completes a serve exchange).
pub fn install_mark_valid(marker: fn() -> i32) {
    GATE.lock().unwrap_or_else(|p| p.into_inner()).arm(marker);
}

/// Whether the gate is armed (diagnostic surface).
pub fn armed() -> bool {
    GATE.lock().unwrap_or_else(|p| p.into_inner()).armed()
}

/// Serve evidence — the product-path entry point. See
/// [`ValidityGate::note_serve_evidence`].
pub fn note_serve_evidence(source: &str) -> bool {
    GATE.lock()
        .unwrap_or_else(|p| p.into_inner())
        .note_serve_evidence(source)
}

/// The platform mark-valid call. Returns the ESP-IDF rc: 0 = marked
/// (was pending-verify), nonzero = not in the pending state (first
/// boot, factory slot, or a bootloader without the rollback state
/// machine) — logged by the gate, never fatal.
#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
fn platform_mark_valid() -> i32 {
    // Safety: ESP-IDF app_update API, idempotent, callable from any task.
    unsafe { esp_idf_sys::esp_ota_mark_app_valid_cancel_rollback() }
}

/// ESP arm: both firmware mains (`firmware.rs` for the M5 boards,
/// `firmware_nucula.rs` for the C3 OTA seat) call this once at boot,
/// before serving. The gate stays inert on host test builds.
#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
pub fn arm_platform() {
    install_mark_valid(platform_mark_valid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Test isolation (ccid Codex-P2 lesson): the fn-pointer shape means
    // every test gets its OWN marker + OWN counter — parallel-runner
    // safe by construction. Only the global-layer test touches [`GATE`],
    // through the race-free private instance first.

    static RUNS_A: AtomicUsize = AtomicUsize::new(0);
    fn marker_a() -> i32 {
        RUNS_A.fetch_add(1, Ordering::SeqCst);
        0
    }
    static RUNS_B: AtomicUsize = AtomicUsize::new(0);
    fn marker_b() -> i32 {
        RUNS_B.fetch_add(1, Ordering::SeqCst);
        0
    }
    static RUNS_C: AtomicUsize = AtomicUsize::new(0);
    fn marker_c() -> i32 {
        // nonzero rc: the "not pending-verify" arm (warn, not fatal).
        RUNS_C.fetch_add(1, Ordering::SeqCst);
        1
    }
    static RUNS_D: AtomicUsize = AtomicUsize::new(0);
    fn marker_d() -> i32 {
        RUNS_D.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[test]
    fn unarmed_gate_is_inert_and_does_not_latch() {
        let mut gate = ValidityGate::new();
        assert!(!gate.armed());
        // Evidence while disarmed: noted, nothing to mark...
        assert!(!gate.note_serve_evidence("test"));
        assert!(!gate.note_serve_evidence("test"));
        assert_eq!(RUNS_A.load(Ordering::SeqCst), 0, "nothing ran");
        // ...and it does NOT consume the gate: arming afterwards still
        // lets the NEXT evidence run the marker.
        assert!(gate.arm(marker_a));
        assert!(gate.note_serve_evidence("test"));
        assert_eq!(RUNS_A.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn first_evidence_runs_marker_once_then_idempotent() {
        let mut gate = ValidityGate::new();
        assert!(gate.arm(marker_b));
        assert!(gate.note_serve_evidence("card-burn"));
        // Every later exchange is a no-op — fire-once per boot.
        assert!(!gate.note_serve_evidence("card-burn"));
        assert!(!gate.note_serve_evidence("rest-2xx"));
        assert_eq!(RUNS_B.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn nonzero_rc_is_logged_not_fatal() {
        // The "not pending-verify" shape (first boot / factory slot /
        // rollback-disabled bootloader): rc != 0 must not panic and the
        // evidence still counts as consumed.
        let mut gate = ValidityGate::new();
        assert!(gate.arm(marker_c));
        assert!(gate.note_serve_evidence("nucula-poll"));
        assert_eq!(RUNS_C.load(Ordering::SeqCst), 1);
        assert!(!gate.note_serve_evidence("nucula-poll"));
        assert_eq!(RUNS_C.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn late_arm_after_first_evidence_is_rejected() {
        // Arming after the marker already ran cannot re-arm the boot.
        let mut gate = ValidityGate::new();
        assert!(gate.arm(marker_d));
        assert!(gate.note_serve_evidence("card-inspect"));
        assert!(!gate.arm(marker_d), "no second chance per boot");
        assert_eq!(RUNS_D.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn global_layer_round_trip() {
        // The installed-fn layer (what the firmware mains and the
        // product-path write sites call). Host tests never arm it for
        // real — arm a counting marker, verify exactly one firing, then
        // restore the disarmed state so sibling tests stay inert.
        static RUNS_G: AtomicUsize = AtomicUsize::new(0);
        fn marker_g() -> i32 {
            RUNS_G.fetch_add(1, Ordering::SeqCst);
            0
        }

        assert!(!armed());
        install_mark_valid(marker_g);
        assert!(armed());
        let _ = note_serve_evidence("global-test");
        let after_first = RUNS_G.load(Ordering::SeqCst);
        assert_eq!(after_first, 1, "first evidence consumed the latch");
        let _ = note_serve_evidence("global-test");
        assert_eq!(
            RUNS_G.load(Ordering::SeqCst),
            after_first,
            "later evidence never re-marks"
        );

        // Restore: disarm + unlatch for any test that runs after this
        // one (the #[cfg(test)] serialization of cargo's default runner
        // is one thread for a single binary's thread-less tests, but be
        // explicit anyway).
        *GATE.lock().unwrap_or_else(|p| p.into_inner()) = ValidityGate::new();
        assert!(!armed());
    }
}
