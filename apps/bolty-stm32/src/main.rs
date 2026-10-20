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
    // (PINOUT-nfc.md). Until an MFRC522 is physically wired this stops at
    // the bus scan; when one answers at 0x28 the transceiver is constructed
    // (from_i2c runs the PCD version check) but no card handling happens.
    #[cfg(feature = "board-stm32f4-disco")]
    mod board {
        use stm32f4xx_hal::{i2c::I2c, pac, prelude::*};

        type HalI2c = I2c<pac::I2C1>;

        /// embedded-hal 1.0 shim over the hal fork's I2c (which implements
        /// the 0.2-era WriteIter/WriteIterRead — see hal_02 re-export).
        /// mfrc522-pcd's `from_i2c` requires e-h 1.0 `I2c`; this adapter is
        /// the bridge so module-arrival day is wiring + flash only.
        /// Semantics: the common write / write-then-read shapes map 1:1;
        /// any other Operation sequence executes sequentially (electrically
        /// separate transactions) — mfrc522 I2C traffic never uses those.
        pub struct Eh1I2c<I>(pub I);

        #[derive(Debug)]
        pub struct AdapterError<E>(pub E);

        impl<E: core::fmt::Debug> embedded_hal::i2c::Error for AdapterError<E> {
            fn kind(&self) -> embedded_hal::i2c::ErrorKind {
                embedded_hal::i2c::ErrorKind::Other
            }
        }

        impl<E: core::fmt::Debug> core::fmt::Display for AdapterError<E> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "i2c bus error: {:?}", self.0)
            }
        }

        impl<I, E> embedded_hal::i2c::ErrorType for Eh1I2c<I>
        where
            I: stm32f4xx_hal::hal_02::blocking::i2c::WriteIter<Error = E>
                + stm32f4xx_hal::hal_02::blocking::i2c::WriteIterRead<Error = E>,
            E: core::fmt::Debug,
        {
            type Error = AdapterError<E>;
        }

        impl<I, E> embedded_hal::i2c::I2c for Eh1I2c<I>
        where
            I: stm32f4xx_hal::hal_02::blocking::i2c::WriteIter<Error = E>
                + stm32f4xx_hal::hal_02::blocking::i2c::WriteIterRead<Error = E>,
            E: core::fmt::Debug,
        {
            fn transaction(
                &mut self,
                address: u8,
                operations: &mut [embedded_hal::i2c::Operation<'_>],
            ) -> Result<(), Self::Error> {
                use embedded_hal::i2c::Operation;

                let mut ops = operations.iter_mut();
                let folded = match (ops.next(), ops.next()) {
                    (Some(Operation::Write(w)), None) => self
                        .0
                        .write(address, w.iter().copied())
                        .map_err(AdapterError),
                    (Some(Operation::Write(w)), Some(Operation::Read(r))) => self
                        .0
                        .write_iter_read(address, w.iter().copied(), r)
                        .map_err(AdapterError),
                    _ => {
                        for op in operations {
                            match op {
                                Operation::Write(w) => {
                                    self.0
                                        .write(address, w.iter().copied())
                                        .map_err(AdapterError)?;
                                }
                                Operation::Read(r) => {
                                    self.0
                                        .write_iter_read(address, core::iter::empty::<u8>(), r)
                                        .map_err(AdapterError)?;
                                }
                            }
                        }
                        Ok(())
                    }
                };
                folded
            }
        }

        pub struct Board {
            // Held for the card-handling phase (naming follows the prior
            // `_i2c` convention: keep-alive until main.rs TODO 4-5 land).
            pub _mfrc522: Option<mfrc522_pcd::Mfrc522Transceiver<Eh1I2c<HalI2c>>>,
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
            if !mfrc522 {
                defmt::warn!(
                    "bolty-stm32: nfc=mfrc522 NOT detected (expected until wiring; scan found {} other device(s))",
                    found
                );
                return Board { _mfrc522: None };
            }

            defmt::info!("bolty-stm32: nfc=mfrc522 detected at 0x28 — constructing transceiver");
            // from_i2c runs the PCD version check on construction: the
            // first real register-level proof the day the module is wired.
            match mfrc522_pcd::Mfrc522Transceiver::from_i2c(
                Eh1I2c(i2c),
                mfrc522_pcd::DEFAULT_I2C_ADDRESS,
            ) {
                Ok(xcvr) => {
                    defmt::info!("bolty-stm32: mfrc522 transceiver ready");
                    Board {
                        _mfrc522: Some(xcvr),
                    }
                }
                Err(_) => {
                    // Not defmt::Format (hal error type) — the panic-free
                    // detail path is gdb/tools on the bench, this is the
                    // marker that construction failed.
                    defmt::error!("bolty-stm32: mfrc522 init failed (bus or version check)");
                    Board { _mfrc522: None }
                }
            }
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
