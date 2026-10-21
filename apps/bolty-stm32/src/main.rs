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
                // Fold ONLY exact 1-op write / 2-op write+read shapes; any
                // other sequence (incl. write+read followed by more ops)
                // falls through to the sequential path — never drop ops.
                let folded = match (ops.next(), ops.next(), ops.next()) {
                    (Some(Operation::Write(w)), None, None) => self
                        .0
                        .write(address, w.iter().copied())
                        .map_err(AdapterError),
                    (Some(Operation::Write(w)), Some(Operation::Read(r)), None) => self
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
            #[cfg(feature = "nfc-pn532")]
            pub _pn532: Option<
                pn532_port::Pn532Device<
                    pn532_port::PortPn532,
                    stm32f4xx_hal::gpio::PB1<
                        stm32f4xx_hal::gpio::Output<stm32f4xx_hal::gpio::PushPull>,
                    >,
                >,
            >,
        }

        /// e-h 1.0 OutputPin shim over the hal fork's pins (same seam
        /// as Eh1I2c: the fork implements the 0.2-era traits).
        // ── PN532 port (compile-proven until the module arrives; option B
        // in docs/stm32-nfc-frontend-plan.md) ─────────────────────────────
        // Everything below mirrors pn532-transport's xtensa-gated blanket
        // impl + ccid's EspDelayTimer design, app-locally so no shared
        // crate changes ride along. When the de-gate lands upstream
        // (ACR-gated lane), this module collapses to a constructor.
        #[cfg(feature = "nfc-pn532")]
        mod pn532_port {
            use stm32f4xx_hal::{gpio, pac, prelude::*, rcc::Rcc, spi::Spi};

            use pn532::spi::SPIInterface;
            use pn532::{CountDown, Pn532};
            pub use pn532_transport::Pn532Device;
            use pn532_transport::Pn532Ops;
            use pn532_transport::PN532_BUF_SIZE;

            // SPI1 on PB3=SCK / PB4=MISO / PB5=MOSI (AF5), CS on PB0 — the
            // PINOUT-nfc.md proposal. TODO at wiring day: verify DIP straps
            // for SPI and the SPI mode against the module silkscreen.
            pub type HalSpi = Spi<pac::SPI1, false, u8>;
            pub type HalCs = gpio::PB0<gpio::Output<gpio::PushPull>>;

            /// e-h 1.0 SpiDevice over the hal fork's Spi + a GPIO CS, with
            /// the WHOLE Operation slice executed under one CS assertion
            /// (PN532 framing requires it — a CS toggle mid-command starts
            /// a new command).
            pub struct CsSpi<SPI, CS> {
                pub spi: SPI,
                pub cs: CS,
            }

            #[derive(Debug)]
            pub enum SpiAdapterError {
                Bus(stm32f4xx_hal::spi::Error),
                Cs,
            }

            impl core::fmt::Display for SpiAdapterError {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    match self {
                        SpiAdapterError::Bus(e) => write!(f, "spi bus error: {e:?}"),
                        SpiAdapterError::Cs => write!(f, "chip-select pin error"),
                    }
                }
            }

            impl embedded_hal::spi::Error for SpiAdapterError {
                fn kind(&self) -> embedded_hal::spi::ErrorKind {
                    embedded_hal::spi::ErrorKind::Other
                }
            }

            impl<SPI, CS> embedded_hal::spi::ErrorType for CsSpi<SPI, CS> {
                type Error = SpiAdapterError;
            }

            impl<SPI, CS> embedded_hal::spi::SpiDevice for CsSpi<SPI, CS>
            where
                SPI: spi_byte_io::SpiByteIo,
                CS: embedded_hal::digital::OutputPin,
            {
                fn transaction(
                    &mut self,
                    operations: &mut [embedded_hal::spi::Operation<'_, u8>],
                ) -> Result<(), Self::Error> {
                    use embedded_hal::spi::Operation;
                    self.cs.set_low().map_err(|_| SpiAdapterError::Cs)?;
                    let result = (|| -> Result<(), SpiAdapterError> {
                        for op in operations {
                            match op {
                                Operation::Write(words) => {
                                    // Full-duplex shift; readback discarded.
                                    for b in words.iter() {
                                        self.spi.byte_transfer(*b).map_err(SpiAdapterError::Bus)?;
                                    }
                                }
                                Operation::Read(buf) => {
                                    for b in buf.iter_mut() {
                                        *b = self
                                            .spi
                                            .byte_transfer(0x00)
                                            .map_err(SpiAdapterError::Bus)?;
                                    }
                                }
                                Operation::Transfer(read, write) => {
                                    // Interleave: shift write bytes while
                                    // collecting into read (dummies once
                                    // write is exhausted).
                                    let mut it = read.iter_mut();
                                    for w in write.iter() {
                                        if let Some(r) = it.next() {
                                            *r = self
                                                .spi
                                                .byte_transfer(*w)
                                                .map_err(SpiAdapterError::Bus)?;
                                        }
                                    }
                                    for r in it {
                                        *r = self
                                            .spi
                                            .byte_transfer(0x00)
                                            .map_err(SpiAdapterError::Bus)?;
                                    }
                                }
                                Operation::TransferInPlace(buf) => {
                                    for b in buf.iter_mut() {
                                        *b = self
                                            .spi
                                            .byte_transfer(*b)
                                            .map_err(SpiAdapterError::Bus)?;
                                    }
                                }
                                Operation::DelayNs(_) => {
                                    // PN532 command streams never interleave
                                    // delays; fail loudly if that changes.
                                    return Err(SpiAdapterError::Cs);
                                }
                            }
                        }
                        Ok(())
                    })();
                    self.cs.set_high().map_err(|_| SpiAdapterError::Cs)?;
                    result
                }
            }

            mod spi_byte_io {
                use stm32f4xx_hal::spi::{Error, Spi};

                /// The fork's Spi byte-level API (write_nonblocking +
                /// read_nonblocking pair), collapsed to a blocking
                /// full-duplex single-byte exchange. Interleaving the
                /// read with every write keeps the RX side from
                /// overrunning.
                pub trait SpiByteIo {
                    fn byte_transfer(&mut self, out: u8) -> Result<u8, Error>;
                }

                impl<SPI: stm32f4xx_hal::spi::Instance> SpiByteIo for Spi<SPI, false, u8> {
                    fn byte_transfer(&mut self, out: u8) -> Result<u8, Error> {
                        loop {
                            match self.write_nonblocking(out) {
                                Ok(()) => break,
                                Err(pn532::nb::Error::Other(e)) => return Err(e),
                                Err(pn532::nb::Error::WouldBlock) => continue,
                            }
                        }
                        loop {
                            match self.read_nonblocking() {
                                Ok(b) => return Ok(b),
                                Err(pn532::nb::Error::Other(e)) => return Err(e),
                                Err(pn532::nb::Error::WouldBlock) => continue,
                            }
                        }
                    }
                }
            }

            /// pn532::CountDown timer that simply busy-waits the armed
            /// duration on wait() — same design as ccid's EspDelayTimer.
            /// Cycle cost derived from the frozen 168 MHz sysclk.
            pub struct BlockingTimer {
                deadline: core::time::Duration,
            }

            impl BlockingTimer {
                pub fn new() -> Self {
                    Self {
                        deadline: core::time::Duration::ZERO,
                    }
                }
            }

            impl CountDown for BlockingTimer {
                type Time = core::time::Duration;

                fn start<T>(&mut self, count: T)
                where
                    T: Into<Self::Time>,
                {
                    self.deadline = count.into();
                }

                fn wait(&mut self) -> pn532::nb::Result<(), core::convert::Infallible> {
                    let us = self.deadline.as_micros() as u32;
                    if us > 0 {
                        // 168 cycles/us at the frozen sysclk; asm::delay is
                        // approximately cycles.
                        cortex_m::asm::delay(us * 168);
                        self.deadline = core::time::Duration::ZERO;
                    }
                    Ok(())
                }
            }

            pub type PortPn532 =
                Pn532<SPIInterface<CsSpi<HalSpi, HalCs>>, BlockingTimer, PN532_BUF_SIZE>;

            /// Wiring-day entry: SPI1 PB3/4/5 @ 1 MHz + CS PB0 + RST PB1
            /// (PINOUT-nfc.md proposal; verify DIP straps + SPI mode at
            /// wiring day). Probes with GetFirmwareVersion; returns None
            /// with a defmt marker when no module answers (bounded by the
            /// 50 ms process timeout — floating MISO cannot hang it).
            #[allow(clippy::too_many_arguments)]
            pub fn probe(
                spi1: pac::SPI1,
                sck: gpio::PB3<gpio::Alternate<5>>,
                miso: gpio::PB4<gpio::Alternate<5>>,
                mosi: gpio::PB5<gpio::Alternate<5>>,
                cs_pin: HalCs,
                rst_pin: gpio::PB1<gpio::Output<gpio::PushPull>>,
                rcc: &mut Rcc,
            ) -> Option<Pn532Device<PortPn532, gpio::PB1<gpio::Output<gpio::PushPull>>>>
            {
                // Mode 0; conservative 1 MHz until the module is verified.
                let spi = Spi::new(
                    spi1,
                    (Some(sck), Some(miso), Some(mosi)),
                    stm32f4xx_hal::spi::Mode {
                        polarity: stm32f4xx_hal::spi::Polarity::IdleLow,
                        phase: stm32f4xx_hal::spi::Phase::CaptureOnFirstTransition,
                    },
                    1.MHz(),
                    rcc,
                );
                let bus = SPIInterface {
                    spi: CsSpi { spi, cs: cs_pin },
                };
                let mut device: Pn532Device<PortPn532, _> =
                    Pn532Device::new(Pn532::new(bus, BlockingTimer::new()), rst_pin);
                match device.raw_pn532_mut().get_firmware_version() {
                    Ok((major, minor)) => {
                        defmt::info!("bolty-stm32: nfc=pn532 detected (fw {}.{})", major, minor);
                        Some(device)
                    }
                    Err(_) => {
                        defmt::warn!("bolty-stm32: nfc=pn532 NOT detected (expected until wiring)");
                        None
                    }
                }
            }
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

            // NFC frontends share GPIOB; extract every pin up front so the
            // partially-moved Parts never travel (PINOUT-nfc.md map).
            #[cfg(feature = "nfc-pn532")]
            let (pn_sck, pn_miso, pn_mosi, pn_cs, pn_rst) = (
                gpiob.pb3.into_alternate::<5>(),
                gpiob.pb4.into_alternate::<5>(),
                gpiob.pb5.into_alternate::<5>(),
                {
                    let mut cs = gpiob.pb0.into_push_pull_output();
                    cs.set_high();
                    cs
                },
                gpiob.pb1.into_push_pull_output(),
            );

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
            let mfrc522 = if !mfrc522 {
                defmt::warn!(
                    "bolty-stm32: nfc=mfrc522 NOT detected (expected until wiring; scan found {} other device(s))",
                    found
                );
                None
            } else {
                defmt::info!(
                    "bolty-stm32: nfc=mfrc522 detected at 0x28 — constructing transceiver"
                );
                // from_i2c runs the PCD version check on construction: the
                // first real register-level proof the day the module is wired.
                match mfrc522_pcd::Mfrc522Transceiver::from_i2c(
                    Eh1I2c(i2c),
                    mfrc522_pcd::DEFAULT_I2C_ADDRESS,
                ) {
                    Ok(xcvr) => {
                        defmt::info!("bolty-stm32: mfrc522 transceiver ready");
                        Some(xcvr)
                    }
                    Err(_) => {
                        // Not defmt::Format (hal error type) — the panic-free
                        // detail path is gdb/tools on the bench, this is the
                        // marker that construction failed.
                        defmt::error!("bolty-stm32: mfrc522 init failed (bus or version check)");
                        None
                    }
                }
            };

            #[cfg(feature = "nfc-pn532")]
            let pn532 =
                pn532_port::probe(dp.SPI1, pn_sck, pn_miso, pn_mosi, pn_cs, pn_rst, &mut rcc);

            Board {
                _mfrc522: mfrc522,
                #[cfg(feature = "nfc-pn532")]
                _pn532: pn532,
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
