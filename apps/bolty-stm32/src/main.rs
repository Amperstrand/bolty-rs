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

// ── STM32 entry point ───────────────────────────────────────────────

#[cfg(all(target_arch = "arm", target_os = "none"))]
mod stm32 {
    use cortex_m_rt::entry;
    use defmt_rtt as _;
    // panic-probe (print-defmt) provides the #[panic_handler]; combined
    // with defmt-rtt this is the standard probe-rs panic path.
    use panic_probe as _;

    #[global_allocator]
    static ALLOC: embedded_alloc::Heap = embedded_alloc::Heap::empty();

    // Hardware init behind the board feature (docs/stm32-nfc-frontend-plan.md,
    // option A). Clock plan mirrors ccid-firmware-rs's F469 config; I2C1
    // alt-map pins PB6/PB7 chosen to avoid every in-tree co-tenant claim
    // (PINOUT-nfc.md). A raw bus scan is all we do until an MFRC522 is
    // physically wired — no PCD register access, no card handling.
    #[cfg(feature = "board-stm32f4-disco")]
    mod board {
        use stm32f4xx_hal::{i2c::I2c, pac, prelude::*};

        pub struct Board {
            pub _i2c: I2c<pac::I2C1>,
        }

        pub fn init(dp: pac::Peripherals) -> Board {
            let mut rcc = dp.RCC.freeze(
                stm32f4xx_hal::rcc::Config::hse(8.MHz())
                    .sysclk(168.MHz())
                    .pclk1(42.MHz())
                    .pclk2(84.MHz())
                    .require_pll48clk(),
            );
            defmt::info!("bolty-stm32: clocks ok (sysclk 168 MHz, hse 8 MHz)");

            let gpiob = dp.GPIOB.split(&mut rcc);
            // PB6 = SCL, PB7 = SDA for I2C1 (alt map; AF conversion is done
            // by I2c::new — same call shape as the BSP touch init).
            let mut i2c = I2c::new(dp.I2C1, (gpiob.pb6, gpiob.pb7), 100.kHz(), &mut rcc);
            defmt::info!("bolty-stm32: i2c1 ok (pb6=scl pb7=sda, 100 kHz)");

            // Bus scan (7-bit). With no NFC module wired yet this proves
            // the bus is electrically sane and reports who else answers
            // (co-tenant/onboard devices) — the plan's checklist item.
            let mut found = 0u8;
            let mut mfrc522 = false;
            for addr in 1u8..=0x7F {
                if i2c.write(addr, &[]).is_ok() {
                    defmt::info!("bolty-stm32: i2c scan: device at 0x{:x}", addr);
                    found += 1;
                    mfrc522 |= addr == mfrc522_pcd::DEFAULT_I2C_ADDRESS;
                }
            }
            if mfrc522 {
                defmt::info!("bolty-stm32: nfc=mfrc522 detected at 0x28");
            } else {
                defmt::warn!(
                    "bolty-stm32: nfc=mfrc522 NOT detected (expected until wiring; scan found {} other device(s))",
                    found
                );
            }

            Board { _i2c: i2c }
        }
    }

    #[entry]
    fn main() -> ! {
        // defmt requires a timestamp provider from the binary (no timers
        // are initialized in the skeleton yet — report a constant).
        defmt::timestamp!("{=u64:us}", 0u64);

        defmt::info!("bolty-stm32: initializing...");

        {
            use core::mem::MaybeUninit;
            const HEAP_SIZE: usize = 64 * 1024;
            static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe {
                ALLOC.init(
                    (&raw const HEAP_MEM) as *const MaybeUninit<u8> as usize,
                    HEAP_SIZE,
                )
            };
        }

        defmt::info!("bolty-stm32: heap initialized ({} bytes)", 64 * 1024);

        #[cfg(feature = "board-stm32f4-disco")]
        let _board = board::init(stm32f4xx_hal::pac::Peripherals::take().unwrap());

        // TODO: Hardware initialization
        // 1. Initialize STM32 clocks (RCC)                  — done (board::init)
        // 2. Initialize I2C peripheral (for MFRC522)        — done (board::init, scan only)
        // 3. Initialize UART (for serial console)           — TODO (USART1 via ST-LINK VCP?)
        // 4. Create Mfrc522Transceiver from I2C             — TODO (module not wired yet; needs
        //                                                    an e-h 1.0 adapter for the hal's I2c)
        // 5. Create Mfrc522Transport                        — TODO (with 4)
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
