//! Bolt Card firmware for STM32 + MFRC522 (bare-metal no_std).
//!
//! This is a skeleton that compiles for both host (for basic type checking)
//! and ARM Cortex-M targets (STM32F4). Full hardware initialization and
//! NFC operations require the `board-stm32f4-disco` feature and a real
//! STM32 target.
//!
//! ## Architecture
//!
//! ```text
//! STM32F469 + MFRC522 (I2C) + UART console
//!   └── bolty-core, bolty-ntag, bolty-mfrc522 (same crates as ESP32)
//! ```
//!
//! ## Build
//!
//! ```bash
//! # Host check (type-checking only)
//! cargo build -p bolty-stm32
//!
//! # STM32F469 target (requires thumbv7em-none-eabihf)
//! cargo build -p bolty-stm32 --target thumbv7em-none-eabihf --features board-stm32f4-disco
//! ```

#![cfg_attr(all(target_arch = "arm", target_os = "none"), no_std)]
#![cfg_attr(all(target_arch = "arm", target_os = "none"), no_main)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Minimal no_std `block_on` — polls a future until completion.
#[allow(dead_code)]
fn block_on<F: Future>(mut future: F) -> F::Output {
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    let waker = futures_task_noop_waker();
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(val) = future.as_mut().poll(&mut cx) {
            return val;
        }
    }
}

#[allow(dead_code)]
fn futures_task_noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}

    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

// ── Target-conditional entry point ──────────────────────────────────

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
fn main() {
    println!("bolty-stm32: host stub (compile check only)");
    println!("Build for STM32 with: cargo build --target thumbv7em-none-eabihf --features board-stm32f4-disco");
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[defmt::panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf();
}

// ── STM32 entry point ───────────────────────────────────────────────

#[cfg(all(target_arch = "arm", target_os = "none"))]
mod stm32 {
    use super::block_on;
    use alloc::boxed::Box;
    use cortex_m_rt::entry;
    use defmt_rtt as _;
    use panic_probe as _;

    #[global_allocator]
    static ALLOC: embedded_alloc::Heap = embedded_alloc::Heap::empty();

    #[entry]
    fn main() -> ! {
        defmt::info!("bolty-stm32: initializing...");

        {
            use core::mem::MaybeUninit;
            const HEAP_SIZE: usize = 64 * 1024;
            static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { ALLOC.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) };
        }

        defmt::info!("bolty-stm32: heap initialized ({} bytes)", 64 * 1024);

        // TODO: Hardware initialization
        // 1. Initialize STM32 clocks (RCC)
        // 2. Initialize I2C peripheral (for MFRC522)
        // 3. Initialize UART (for serial console)
        // 4. Create Mfrc522Transceiver from I2C
        // 5. Create Mfrc522Transport
        //
        // The code below shows the intended API usage:
        //
        // let i2c = stm32f4xx_hal::i2c::I2c::new(dp.I2C1, (scl, sda), 100.kHz(), &clocks);
        // let xcvr = mfrc522_pcd::Mfrc522Transceiver::from_i2c(i2c, mfrc522_pcd::DEFAULT_I2C_ADDRESS)?;
        // let mut transport = bolty_mfrc522::Mfrc522Transport::activate(&mut xcvr)?;
        //
        // let params = bolty_ntag::BurnParams { ... };
        // let result = block_on(bolty_ntag::burn(&mut transport, &params, rnd_a))?;
        //
        // Same bolty-core / bolty-ntag / bolty-mfrc522 crates as ESP32!
        // Only the HAL layer changes: stm32f4xx-hal instead of esp-idf-hal.

        defmt::info!("bolty-stm32: skeleton ready — implement hardware init");
        loop {
            cortex_m::asm::wfi();
        }
    }
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern crate alloc;
