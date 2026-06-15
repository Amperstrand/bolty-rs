//! MFRC522 PcdTransceiver for ISO 14443 Type A communication.
//!
//! Bridges the MFRC522 chip to the `iso14443::type_a::PcdTransceiver` trait.
//! This crate has NO dependency on ntag424 — it is purely the PCD (Proximity
//! Coupling Device) layer, suitable for sharing across projects that need
//! raw ISO 14443 frame exchange.
//!
//! `#![no_std]`-compatible (uses `alloc`).

#![no_std]

extern crate alloc;

use embedded_hal::i2c::I2c;
use iso14443::type_a::vec::FrameVec;
use mfrc522::{Initialized, Mfrc522, Register, RxGain, comm::blocking::i2c::I2cInterface};

pub use iso14443::type_a::{Frame, PcdTransceiver};
pub use mfrc522::Error as Mfrc522Error;

pub const DEFAULT_I2C_ADDRESS: u8 = 0x28;

pub struct Mfrc522Transceiver<I2C: I2c> {
    pub mfrc522: Mfrc522<I2cInterface<I2C>, Initialized>,
}

impl<I2C: I2c> Mfrc522Transceiver<I2C> {
    pub fn new(mfrc522: Mfrc522<I2cInterface<I2C>, Initialized>) -> Self {
        Self { mfrc522 }
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

    fn reset_frontend(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.mfrc522.write_register(Register::TxModeReg, 0x00)?;
        self.mfrc522.write_register(Register::RxModeReg, 0x00)?;
        self.mfrc522.write_register(Register::ModWidthReg, 0x26)?;
        self.mfrc522.write_register(Register::TxASKReg, 0x40)?;
        self.mfrc522
            .write_register(Register::ModeReg, (0x3f & !0b11) | 0b01)?;
        Ok(())
    }

    pub fn prepare_for_activation(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.soft_reset()?;
        self.reset_frontend()?;
        self.mfrc522
            .rmw_register(Register::TxControlReg, |b| b & !0b11)?;
        for _ in 0..4 {
            self.mfrc522.write_register(Register::FIFOLevelReg, 0x80)?;
        }
        self.mfrc522
            .rmw_register(Register::TxControlReg, |b| b | 0b11)?;
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

        // SAFETY: len is clamped via .min(fifo.buffer.len()) in each arm.
        #[allow(clippy::indexing_slicing)]
        let response = match frame {
            Frame::Short(data) => {
                let fifo = self.mfrc522.transceive::<2>(data.as_slice(), 7, 0)?;
                if fifo.valid_bits != 0 {
                    return Err(Mfrc522Error::Protocol);
                }
                let len = fifo.valid_bytes.min(fifo.buffer.len());
                fifo.buffer[..len].to_vec()
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
                fifo.buffer[..len].to_vec()
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
                fifo.buffer[..len].to_vec()
            }
        };

        Ok(response)
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), Self::Error> {
        Err(Mfrc522Error::Protocol)
    }

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
