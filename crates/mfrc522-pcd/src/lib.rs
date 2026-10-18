//! MFRC522 PcdTransceiver for ISO 14443 Type A communication.
//!
//! Bridges the MFRC522 chip to the `iso14443::type_a::PcdTransceiver` trait.
//! This crate has NO dependency on ntag424 — it is purely the PCD (Proximity
//! Coupling Device) layer, suitable for sharing across projects that need
//! raw ISO 14443 frame exchange.
//!
//! `#![no_std]`-compatible (uses `alloc`).

#![no_std]

pub extern crate alloc;

use embedded_hal::delay::DelayNs;
use embedded_hal::i2c::I2c;
use iso14443::type_a::vec::FrameVec;
use mfrc522::{Initialized, Mfrc522, Register, RxGain, comm::blocking::i2c::I2cInterface};

pub use iso14443::type_a::{Frame, PcdTransceiver};
pub use mfrc522::Error as Mfrc522Error;

pub const DEFAULT_I2C_ADDRESS: u8 = 0x28;

/// Field-off dwell for the antenna cycle in
/// [`Mfrc522Transceiver::prepare_for_activation_with_delays`].
///
/// A PICC whose ISO-14443-4 layer wedged mid-chain (e.g. a stalled host
/// transfer) keeps answering WUPA but ignores RATS until the field
/// de-energizes it; 50 ms is what a charge-pump-powered card needs to
/// fully reset (bench-proven on ccid-firmware-rs, commit 89382e6, against
/// a J3R180 JavaCard — the answer is WUPA-alive but RATS-dead without it).
///
/// Only ever paid on the idle poll / activation path — never with a
/// response pending.
pub const FIELD_OFF_DWELL_MS: u32 = 50;

/// Field-on settle after the antenna is re-energized in
/// [`Mfrc522Transceiver::prepare_for_activation_with_delays`] — lets the
/// charge pump stabilize before the first REQA/WUPA.
pub const FIELD_ON_SETTLE_MS: u32 = 5;

/// A no-op [`DelayNs`]: preserves the pre-dwell antenna-cycle timing for
/// callers that cannot provide a real delay (host unit tests, transports
/// without a timer). Prefer injecting a yielding delay on hardware —
/// busy-waiting through field dwells starves the scheduler and, on ESP-IDF,
/// trips the task watchdog (ccid-firmware-rs issues #63/#80 root cause).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDelay;

impl DelayNs for NoDelay {
    fn delay_ns(&mut self, _ns: u32) {}
}

/// [`DelayNs`] adapter over a plain millisecond function pointer — lets
/// platform-generic callers (the firmware service layer) inject a real
/// delay without threading a second generic parameter through every
/// consumer.
#[derive(Debug, Clone, Copy)]
pub struct FnDelay(pub fn(u32));

impl DelayNs for FnDelay {
    fn delay_ns(&mut self, ns: u32) {
        // Ceiling division: never under-delay.
        (self.0)(ns.div_ceil(1_000_000))
    }
}

/// Higher-level error type providing semantic context over [`Mfrc522Error`].
///
/// [`Mfrc522Error`] remains the [`PcdTransceiver::Error`] associated type for
/// backward compatibility; use [`Error::from`] to convert.
#[derive(Debug)]
pub enum Error<E> {
    Communication(E),
    Timeout,
    Protocol,
    BufferOverflow,
}

impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Communication(e) => write!(f, "MFRC522 communication error: {e:?}"),
            Error::Timeout => write!(f, "MFRC522 timeout"),
            Error::Protocol => write!(f, "MFRC522 protocol error"),
            Error::BufferOverflow => write!(f, "MFRC522 buffer overflow"),
        }
    }
}

impl<E: core::fmt::Debug> core::error::Error for Error<E> {}

impl<E> From<Mfrc522Error<E>> for Error<E> {
    fn from(e: Mfrc522Error<E>) -> Self {
        match e {
            Mfrc522Error::Comm(inner) => Error::Communication(inner),
            Mfrc522Error::Timeout => Error::Timeout,
            Mfrc522Error::Protocol => Error::Protocol,
            Mfrc522Error::BufferOverflow | Mfrc522Error::NoRoom => Error::BufferOverflow,
            // All remaining variants (Bcc, Collision, Crc, IncompleteFrame,
            // Overheating, Parity, Wr, Nak, Proprietary) are NFC protocol
            // level issues.
            _ => Error::Protocol,
        }
    }
}

pub struct Mfrc522Transceiver<I2C: I2c> {
    mfrc522: Mfrc522<I2cInterface<I2C>, Initialized>,
}

impl<I2C: I2c> Mfrc522Transceiver<I2C> {
    pub fn new(mfrc522: Mfrc522<I2cInterface<I2C>, Initialized>) -> Self {
        Self { mfrc522 }
    }

    pub fn raw(&mut self) -> &mut Mfrc522<I2cInterface<I2C>, Initialized> {
        &mut self.mfrc522
    }

    pub fn from_i2c(i2c: I2C, address: u8) -> Result<Self, Mfrc522Error<I2C::Error>> {
        let interface = I2cInterface::new(i2c, address);
        let mut mfrc522 = Mfrc522::new(interface).init()?;
        mfrc522.set_antenna_gain(RxGain::DB33)?;
        Ok(Self::new(mfrc522))
    }

    pub fn release(self) -> I2C {
        self.mfrc522.release().release()
    }

    /// Maximum number of register polls to wait for the MFRC522 PowerDown bit
    /// to clear during a soft reset. The MFRC522 datasheet specifies the reset
    /// completes within a few milliseconds. On a 100 kHz I2C bus, each poll
    /// takes ~0.3 ms, so 1024 polls ≈ 300 ms — well beyond any expected reset
    /// time. If this limit is exceeded the chip is in an unrecoverable state.
    const SOFT_RESET_MAX_POLLS: usize = 1024;

    fn soft_reset(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.mfrc522.write_register(Register::CommandReg, 0x0F)?;
        for _ in 0..Self::SOFT_RESET_MAX_POLLS {
            if self.mfrc522.read_register(Register::CommandReg)? & 0x10 == 0 {
                return Ok(());
            }
        }
        Err(Mfrc522Error::Timeout)
    }

    pub fn reset_frontend(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.mfrc522.write_register(Register::TxModeReg, 0x00)?;
        self.mfrc522.write_register(Register::RxModeReg, 0x00)?;
        self.mfrc522.write_register(Register::ModWidthReg, 0x26)?;
        self.mfrc522.write_register(Register::TxASKReg, 0x40)?;
        self.mfrc522
            .write_register(Register::ModeReg, (0x3f & !0b11) | 0b01)?;
        Ok(())
    }

    pub fn prepare_for_activation(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.prepare_for_activation_with_delays(&mut NoDelay)
    }

    /// Soft reset + frontend reset + antenna cycle with field-off dwell
    /// ([`FIELD_OFF_DWELL_MS`]) and field-on settle ([`FIELD_ON_SETTLE_MS`])
    /// spent through `delay`. On hardware pass a scheduler-yielding delay
    /// (e.g. `esp_idf_hal::delay::FreeRtos`), never a busy-wait.
    pub fn prepare_for_activation_with_delays<D: DelayNs>(
        &mut self,
        delay: &mut D,
    ) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.soft_reset()?;
        self.reset_frontend()?;
        self.mfrc522
            .rmw_register(Register::TxControlReg, |b| b & !0b11)?;
        delay.delay_ms(FIELD_OFF_DWELL_MS);
        for _ in 0..4 {
            self.mfrc522.write_register(Register::FIFOLevelReg, 0x80)?;
        }
        self.mfrc522
            .rmw_register(Register::TxControlReg, |b| b | 0b11)?;
        delay.delay_ms(FIELD_ON_SETTLE_MS);
        self.mfrc522.set_antenna_gain(RxGain::DB33)?;
        Ok(())
    }

    pub fn set_timeout_ms(&mut self, ms: u32) -> Result<(), Mfrc522Error<I2C::Error>> {
        let prescaler = 0xA9u16;
        let timer_hz = 13_560_000u32 / (2 * prescaler as u32 + 1);
        let reload = (ms.saturating_mul(timer_hz) / 1000).min(0xFFFF);

        self.mfrc522.write_register(Register::TModeReg, 0x80)?;
        self.mfrc522
            .write_register(Register::TPrescalerReg, prescaler as u8)?;
        self.mfrc522
            .write_register(Register::TReloadRegHigh, (reload >> 8) as u8)?;
        self.mfrc522
            .write_register(Register::TReloadRegLow, reload as u8)?;
        Ok(())
    }

    pub fn enable_hw_crc(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.mfrc522
            .rmw_register(Register::TxModeReg, |v| v | 0x80)?;
        self.mfrc522
            .rmw_register(Register::RxModeReg, |v| v | 0x80)?;
        Ok(())
    }
}

impl<I2C: I2c> PcdTransceiver for Mfrc522Transceiver<I2C> {
    type Error = Mfrc522Error<I2C::Error>;

    fn transceive(&mut self, frame: &Frame) -> Result<FrameVec, Self::Error> {
        self.mfrc522
            .rmw_register(Register::CollReg, |value| value & !0x80)?;

        let response = match frame {
            Frame::Short(data) => {
                let fifo = self.mfrc522.transceive::<2>(data.as_slice(), 7, 0)?;
                if fifo.valid_bits != 0 {
                    return Err(Mfrc522Error::Protocol);
                }
                let len = fifo.valid_bytes.min(fifo.buffer.len());
                fifo.buffer
                    .get(..len)
                    .ok_or(Mfrc522Error::BufferOverflow)?
                    .to_vec()
            }
            Frame::BitOriented(data) => {
                let tx_last_bits = data.get(1).copied().unwrap_or_default() & 0x07;
                let fifo =
                    self.mfrc522
                        .transceive::<5>(data.as_slice(), tx_last_bits, tx_last_bits)?;
                if fifo.valid_bits != 0 {
                    return Err(Mfrc522Error::Protocol);
                }
                let len = fifo.valid_bytes.min(fifo.buffer.len());
                fifo.buffer
                    .get(..len)
                    .ok_or(Mfrc522Error::BufferOverflow)?
                    .to_vec()
            }
            Frame::Standard(data) => {
                let fifo = match self.mfrc522.transceive::<64>(data.as_slice(), 0, 0) {
                    Ok(f) => f,
                    Err(Mfrc522Error::Crc) => {
                        log_crc_error(&mut self.mfrc522);
                        return Err(Mfrc522Error::Crc);
                    }
                    Err(e) => return Err(e),
                };
                if fifo.valid_bits != 0 {
                    return Err(Mfrc522Error::Protocol);
                }
                let len = fifo.valid_bytes.min(fifo.buffer.len());
                fifo.buffer
                    .get(..len)
                    .ok_or(Mfrc522Error::BufferOverflow)?
                    .to_vec()
            }
        };

        Ok(response)
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), Self::Error> {
        Err(Mfrc522Error::Protocol)
    }
}

impl<I2C: I2c> iso14443_session::TimeoutExt for Mfrc522Transceiver<I2C> {
    fn try_set_timeout_ms(&mut self, ms: u32) -> Result<(), ()> {
        self.set_timeout_ms(ms).map_err(|_| ())
    }
}

fn log_crc_error<I2C: I2c>(mfrc522: &mut Mfrc522<I2cInterface<I2C>, Initialized>) {
    let irq = mfrc522.read_register(Register::ComIrqReg).unwrap_or(0xFF);
    let err = mfrc522.read_register(Register::ErrorReg).unwrap_or(0xFF);
    let level = mfrc522.read_register(Register::FIFOLevelReg).unwrap_or(0) as usize;
    log::warn!(
        "MFRC522 CRC error: ComIrq=0x{:02X} Err=0x{:02X} FIFO={} bytes",
        irq,
        err,
        level
    );
}

#[cfg(target_arch = "xtensa")]
pub mod bus_recovery;

#[cfg(target_arch = "xtensa")]
pub use bus_recovery::{BusRecovery, recover_i2c_bus};

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        // Register-file indexing: every index is a compile-time MFRC522
        // register constant < 0x40 — the panicking case is unrepresentable.
        clippy::indexing_slicing,
        clippy::string_slice
    )]

    use super::*;
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use embedded_hal::i2c::Operation;

    fn reg_index(reg: u8) -> usize {
        usize::from(reg)
    }

    // Register addresses (MFRC522 datasheet chapter 9; mirrored here so the
    // tests can assert against the mock's write log without importing the
    // enum's discriminants indirectly).
    const COMMAND_REG: u8 = 0x01;
    const FIFO_LEVEL_REG: u8 = 0x0A;
    const MODE_REG: u8 = 0x11;
    const TX_MODE_REG: u8 = 0x12;
    const RX_MODE_REG: u8 = 0x13;
    const TX_CONTROL_REG: u8 = 0x14;
    const MOD_WIDTH_REG: u8 = 0x24;
    const RF_CFG_REG: u8 = 0x26;
    const T_MODE_REG: u8 = 0x2A;
    const T_PRESCALER_REG: u8 = 0x2B;
    const T_RELOAD_HIGH_REG: u8 = 0x2C;
    const T_RELOAD_LOW_REG: u8 = 0x2D;

    /// Stateful MFRC522 register-file mock: single-register writes persist,
    /// reads return the stored byte, and every write is recorded so tests
    /// can assert the exact register program order.
    #[derive(Debug)]
    struct MockI2c {
        regs: [u8; 0x40],
        reg_pointer: u8,
        writes: Vec<(u8, u8)>,
        reads: Vec<u8>,
        command_reads: usize,
        /// Wedge CommandReg into permanent PowerDown after this many reads
        /// of it — must exceed the one read mfrc522's own `init()` reset
        /// does (that loop is UNBOUNDED upstream, so the wedge may only
        /// start afterwards; bolty's soft_reset is the bounded one).
        power_down_stuck_after: usize,
    }

    impl Default for MockI2c {
        fn default() -> Self {
            Self {
                regs: [0u8; 0x40],
                reg_pointer: 0,
                writes: Vec::new(),
                reads: Vec::new(),
                command_reads: 0,
                power_down_stuck_after: usize::MAX,
            }
        }
    }

    impl MockI2c {
        /// Mock whose CommandReg wedges into PowerDown after `after`
        /// further reads of it (must exceed init()'s one read — mfrc522's
        /// upstream reset poll is UNBOUNDED; only bolty's bounded soft_reset
        /// may observe the wedge).
        fn wedged_after(after: usize) -> Self {
            Self {
                power_down_stuck_after: after,
                ..Self::default()
            }
        }

        fn reg(&self, reg: u8) -> u8 {
            self.regs[reg_index(reg)]
        }

        fn writes_to(&self, reg: u8) -> Vec<u8> {
            self.writes
                .iter()
                .filter(|(r, _)| *r == reg)
                .map(|(_, v)| *v)
                .collect()
        }

        fn last_write_to(&self, reg: u8) -> u8 {
            *self
                .writes
                .iter()
                .filter(|(r, _)| *r == reg)
                .map(|(_, v)| v)
                .next_back()
                .unwrap_or(&0)
        }

        fn read_reg(&mut self, reg: u8, buf: &mut [u8]) {
            self.reads.push(reg);
            let wedged = reg == COMMAND_REG && self.command_reads >= self.power_down_stuck_after;
            if reg == COMMAND_REG {
                self.command_reads += 1;
            }
            if wedged {
                buf.fill(0x10);
            } else {
                buf.fill(self.regs[reg_index(reg)]);
            }
        }
    }

    impl embedded_hal::i2c::ErrorType for MockI2c {
        type Error = Infallible;
    }

    impl I2c for MockI2c {
        fn transaction(
            &mut self,
            _address: u8,
            operations: &mut [Operation<'_>],
        ) -> Result<(), Self::Error> {
            // eh-1.0's provided write_read/read/write are single transaction
            // calls with these exact operation shapes.
            match operations {
                [Operation::Write(w)] if w.len() == 2 => {
                    self.regs[usize::from(w[0])] = w[1];
                    self.writes.push((w[0], w[1]));
                }
                [Operation::Write(w), Operation::Read(buf)] if w.len() == 1 => {
                    let reg = w[0];
                    self.reg_pointer = reg;
                    self.read_reg(reg, buf);
                }
                [Operation::Write(w)] if w.len() == 1 => {
                    self.reg_pointer = w[0];
                }
                [Operation::Read(buf)] => {
                    let reg = self.reg_pointer;
                    self.read_reg(reg, buf);
                }
                _ => {}
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingDelay {
        ms_calls: Vec<u32>,
    }

    impl DelayNs for RecordingDelay {
        fn delay_ns(&mut self, _ns: u32) {}
        fn delay_ms(&mut self, ms: u32) {
            self.ms_calls.push(ms);
        }
    }

    #[test]
    fn no_delay_is_zero_cost() {
        let mut d = NoDelay;
        d.delay_ms(FIELD_OFF_DWELL_MS);
        d.delay_us(1);
        d.delay_ns(1);
    }

    #[test]
    fn fn_delay_rounds_ns_up_to_whole_ms() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static MS: AtomicU32 = AtomicU32::new(0);
        fn record(ms: u32) {
            MS.fetch_add(ms, Ordering::SeqCst);
        }
        let mut d = FnDelay(record);
        d.delay_ns(1);
        assert_eq!(MS.load(Ordering::SeqCst), 1);
        d.delay_ms(50);
        assert_eq!(MS.load(Ordering::SeqCst), 51);
    }

    #[test]
    fn dwell_constants_match_bench_proven_values() {
        assert_eq!(FIELD_OFF_DWELL_MS, 50);
        assert_eq!(FIELD_ON_SETTLE_MS, 5);
    }

    #[test]
    fn prepare_with_delays_spends_dwell_then_settle() {
        let mock = MockI2c::default();
        let mut t = Mfrc522Transceiver::from_i2c(mock, DEFAULT_I2C_ADDRESS).unwrap();
        let mut delay = RecordingDelay::default();
        t.prepare_for_activation_with_delays(&mut delay).unwrap();
        assert_eq!(
            delay.ms_calls,
            alloc::vec![FIELD_OFF_DWELL_MS, FIELD_ON_SETTLE_MS]
        );
    }

    #[test]
    fn legacy_prepare_never_delays() {
        let mock = MockI2c::default();
        let mut t = Mfrc522Transceiver::from_i2c(mock, DEFAULT_I2C_ADDRESS).unwrap();
        t.prepare_for_activation().unwrap();
    }

    #[test]
    fn prepare_programs_frontend_reset_then_antenna_cycle() {
        let mock = MockI2c::default();
        let mut t = Mfrc522Transceiver::from_i2c(mock, DEFAULT_I2C_ADDRESS).unwrap();
        let mut delay = RecordingDelay::default();
        t.prepare_for_activation_with_delays(&mut delay).unwrap();

        let i2c = t.release();
        assert_eq!(i2c.last_write_to(TX_MODE_REG), 0x00);
        assert_eq!(i2c.last_write_to(RX_MODE_REG), 0x00);
        assert_eq!(i2c.last_write_to(MOD_WIDTH_REG), 0x26);
        assert_eq!(i2c.last_write_to(MODE_REG), (0x3f & !0b11) | 0b01);
        assert_eq!(
            i2c.writes_to(FIFO_LEVEL_REG),
            alloc::vec![0x80, 0x80, 0x80, 0x80]
        );
        let gain_writes = i2c.writes_to(RF_CFG_REG);
        assert!(
            gain_writes.contains(&0x40),
            "RxGain::DB33 not applied: {gain_writes:?}"
        );
        assert!(
            i2c.reads.contains(&TX_CONTROL_REG),
            "TxControlReg rmw must read before write"
        );
    }

    #[test]
    fn soft_reset_poll_is_bounded_when_power_down_never_clears() {
        // Wedge after init()'s single CommandReg read: only bolty's bounded
        // soft_reset poll may observe the wedge.
        let mut t =
            Mfrc522Transceiver::from_i2c(MockI2c::wedged_after(1), DEFAULT_I2C_ADDRESS).unwrap();
        let err = t.prepare_for_activation().unwrap_err();
        assert!(matches!(err, Mfrc522Error::Timeout));
        let i2c = t.release();
        let polls = i2c.reads.iter().filter(|&&r| r == COMMAND_REG).count();
        assert_eq!(
            polls,
            Mfrc522Transceiver::<MockI2c>::SOFT_RESET_MAX_POLLS + 1
        );
    }

    #[test]
    fn set_timeout_ms_maps_ms_onto_timer_registers() {
        let mock = MockI2c::default();
        let mut t = Mfrc522Transceiver::from_i2c(mock, DEFAULT_I2C_ADDRESS).unwrap();

        // f_timer = 13.56 MHz / (2*0xA9 + 1) = 40 kHz → 50 ms = 2000 = 0x07D0
        // (deliberately differs from init()'s 100 ms Arduino default so the
        // test proves OUR mapping, not init's).
        t.set_timeout_ms(50).unwrap();
        let i2c = t.release();
        assert_eq!(i2c.last_write_to(T_MODE_REG), 0x80);
        assert_eq!(i2c.last_write_to(T_PRESCALER_REG), 0xA9);
        assert_eq!(i2c.last_write_to(T_RELOAD_HIGH_REG), 0x07);
        assert_eq!(i2c.last_write_to(T_RELOAD_LOW_REG), 0xD0);
    }

    #[test]
    fn set_timeout_ms_clamps_to_16_bit_reload() {
        let mock = MockI2c::default();
        let mut t = Mfrc522Transceiver::from_i2c(mock, DEFAULT_I2C_ADDRESS).unwrap();
        t.set_timeout_ms(u32::MAX).unwrap();
        let i2c = t.release();
        assert_eq!(i2c.last_write_to(T_RELOAD_HIGH_REG), 0xFF);
        assert_eq!(i2c.last_write_to(T_RELOAD_LOW_REG), 0xFF);
    }

    #[test]
    fn mock_registers_roundtrip() {
        let mut mock = MockI2c::default();
        mock.regs[usize::from(TX_CONTROL_REG)] = 0b11;
        let mut t = Mfrc522Transceiver::from_i2c(mock, DEFAULT_I2C_ADDRESS).unwrap();
        let antenna_on = t.raw().read_register(Register::TxControlReg).unwrap();
        assert_eq!(antenna_on & 0b11, 0b11);
        let i2c = t.release();
        assert_eq!(i2c.reg(TX_CONTROL_REG) & 0b11, 0b11);
    }
}
