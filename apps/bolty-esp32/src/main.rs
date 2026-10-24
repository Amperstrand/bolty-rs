#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
use core::future::Future;
#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
use core::pin::pin;
#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
use core::task::{Context, Poll, Waker};

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("future yielded unexpectedly"),
    }
}

#[cfg(all(any(target_arch = "xtensa", target_arch = "riscv32"), feature = "wifi"))]
mod wifi;

// OTA seat server (:3232) — the bench recovery door (issue #115).
#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    feature = "ota-server"
))]
mod ota_server;

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "rest")]
mod rest;

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "rest")]
mod cert_gen;

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "rest")]
mod tls;

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "ota")]
mod ota;

#[cfg(all(target_arch = "xtensa", feature = "ble"))]
mod ble;

#[cfg(all(target_arch = "xtensa", feature = "display-st7789"))]
mod display;

#[cfg(all(target_arch = "xtensa", feature = "board-m5stick"))]
mod button;

// Boards without physical buttons (M5Atom) get the no-op module so shared
// code (console, hwtest, main loop) compiles without per-site cfgs. That
// shared code is all xtensa-gated, so the stub is too — host test builds
// (which compile only the pure logic modules below) never need it.
#[cfg(all(target_arch = "xtensa", not(feature = "board-m5stick")))]
#[path = "button_stub.rs"]
mod button;

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    all(feature = "board-m5atom", feature = "board-m5stick")
))]
compile_error!(
    "Enable exactly one board feature: `board-m5atom`, `board-m5stick` or `board-nucula`."
);

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    not(any(
        feature = "board-m5atom",
        feature = "board-m5stick",
        feature = "board-nucula"
    ))
))]
compile_error!("Enable one board feature: `board-m5atom`, `board-m5stick` or `board-nucula`.");

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    feature = "board-nucula",
    any(feature = "board-m5atom", feature = "board-m5stick")
))]
compile_error!("`board-nucula` excludes the M5 board features.");

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    not(feature = "board-nucula"),
    not(feature = "nfc-mfrc522")
))]
compile_error!("The M5 board firmware requires the `nfc-mfrc522` feature.");

#[cfg(all(
    target_arch = "xtensa",
    feature = "led-matrix",
    not(feature = "board-m5atom")
))]
compile_error!("`led-matrix` is only supported on `board-m5atom`.");

#[cfg(all(
    target_arch = "xtensa",
    feature = "display-st7789",
    not(feature = "board-m5stick")
))]
compile_error!("`display-st7789` is only supported on `board-m5stick`.");

// Pure logic (parsing, service trait, dispatch) has no esp-idf deps, so it
// also compiles on host — that makes its #[cfg(test)] tests runnable with
// `cargo test -p bolty-esp32` (issue #63: they never executed anywhere).
// The AXP192 register map is pure data in the same boat: its GREAT
// EXPECTATION lock runs on host even though display.rs is xtensa-only.
// Board frontend selection (issue #115): the M5 boards (xtensa) keep the
// MFRC522 firmware module; the nucula (ESP32-C3, riscv32) compiles its own
// PN7160 frontend in its place. Same module name, so main() dispatch and
// every shared reference stay board-agnostic.
#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    not(feature = "board-nucula")
))]
mod firmware;

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    feature = "board-nucula"
))]
#[path = "firmware_nucula.rs"]
mod firmware;

mod axp192_map;
mod commands;
mod console_framing;
mod service;
mod workflow;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
fn main() {
    firmware::main();
}

#[cfg(not(any(target_arch = "xtensa", target_arch = "riscv32")))]
fn main() {
    println!("bolty-esp32 firmware main is only available on esp32 targets");
}
