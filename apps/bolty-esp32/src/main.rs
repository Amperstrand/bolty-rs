#[cfg(target_arch = "xtensa")]
use core::future::Future;
#[cfg(target_arch = "xtensa")]
use core::pin::pin;
#[cfg(target_arch = "xtensa")]
use core::task::{Context, Poll, Waker};

#[cfg(target_arch = "xtensa")]
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("future yielded unexpectedly"),
    }
}

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "wifi")]
mod wifi;

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
    target_arch = "xtensa",
    feature = "board-m5atom",
    feature = "board-m5stick"
))]
compile_error!("Enable exactly one board feature: `board-m5atom` or `board-m5stick`.");

#[cfg(all(
    target_arch = "xtensa",
    not(any(feature = "board-m5atom", feature = "board-m5stick"))
))]
compile_error!("Enable one board feature: `board-m5atom` or `board-m5stick`.");

#[cfg(all(target_arch = "xtensa", not(feature = "nfc-mfrc522")))]
compile_error!("The current firmware requires the `nfc-mfrc522` feature.");

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
mod commands;
#[cfg(target_arch = "xtensa")]
mod firmware;
mod service;
mod workflow;

#[cfg(target_arch = "xtensa")]
fn main() {
    firmware::main();
}

#[cfg(not(target_arch = "xtensa"))]
fn main() {
    println!("bolty-esp32 firmware main is only available on xtensa targets");
}
