#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

use embedded_hal::i2c::I2c;
use iso14443::type_a::{
    Ats, Cid, Frame, Fsdi, PcdTransceiver, activation,
    pcd::{PcdError, PcdSession},
    vec::FrameVec,
};
use mfrc522::{
    Error as Mfrc522Error, Initialized, Mfrc522, Register, RxGain,
    comm::blocking::i2c::I2cInterface,
};
use ntag424::{Response, Transport};

pub const DEFAULT_I2C_ADDRESS: u8 = 0x28;

pub struct Mfrc522Transceiver<I2C: I2c> {
    pub mfrc522: Mfrc522<I2cInterface<I2C>, Initialized>,
}

impl<I2C: I2c> Mfrc522Transceiver<I2C> {
    pub fn new(mfrc522: Mfrc522<I2cInterface<I2C>, Initialized>) -> Self {
        Self { mfrc522 }
    }

    pub fn from_i2c(i2c: I2C, address: u8) -> Result<Self, Error<I2C::Error>> {
        let interface = I2cInterface::new(i2c, address);
        let mut mfrc522 = Mfrc522::new(interface).init().map_err(Error::Mfrc522)?;
        mfrc522
            .set_antenna_gain(RxGain::DB33)
            .map_err(Error::Mfrc522)?;
        Ok(Self::new(mfrc522))
    }

    pub fn release(self) -> I2C {
        self.mfrc522.release().release()
    }

    fn soft_reset(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.mfrc522.write_register(Register::CommandReg, 0x0F)?;
        while self
            .mfrc522
            .read_register(Register::CommandReg)?
            & 0x10
            != 0
        {}
        Ok(())
    }

    fn reset_frontend(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
        self.mfrc522.write_register(Register::TxModeReg, 0x00)?;
        self.mfrc522.write_register(Register::RxModeReg, 0x00)?;
        self.mfrc522.write_register(Register::ModWidthReg, 0x26)?;
        self.mfrc522
            .write_register(Register::TxASKReg, 0x40)?;
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
            self.mfrc522
                .write_register(Register::FIFOLevelReg, 0x80)?;
        }
        self.mfrc522
            .rmw_register(Register::TxControlReg, |b| b | 0b11)?;
        self.mfrc522.set_antenna_gain(RxGain::DB33)?;
        Ok(())
    }

    fn set_timeout_ms(&mut self, ms: u32) -> Result<(), Mfrc522Error<I2C::Error>> {
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

    fn enable_hw_crc(&mut self) -> Result<(), Mfrc522Error<I2C::Error>> {
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
                fifo.buffer[..fifo.valid_bytes].to_vec()
            }
            Frame::BitOriented(data) => {
                let tx_last_bits = data.get(1).copied().unwrap_or_default() & 0x07;
                let fifo =
                    self.mfrc522
                        .transceive::<5>(data.as_slice(), tx_last_bits, tx_last_bits)?;
                if fifo.valid_bits != 0 {
                    return Err(Mfrc522Error::Protocol);
                }
                fifo.buffer[..fifo.valid_bytes].to_vec()
            }
            Frame::Standard(data) => {
                let fifo = self.mfrc522.transceive::<64>(data.as_slice(), 0, 0)?;
                if fifo.valid_bits != 0 {
                    return Err(Mfrc522Error::Protocol);
                }
                fifo.buffer[..fifo.valid_bytes].to_vec()
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

/// NFC transport over MFRC522, borrowing the transceiver for the card session lifetime.
///
/// The transceiver is NOT consumed — `activate()` takes `&mut`, so the caller
/// retains ownership and can re-activate after the card is released.
pub struct Mfrc522Transport<'a, I2C: I2c> {
    transceiver: &'a mut Mfrc522Transceiver<I2C>,
    session: PcdSession,
    uid: Vec<u8>,
}

impl<'a, I2C: I2c> Mfrc522Transport<'a, I2C> {
    pub fn activate(
        transceiver: &'a mut Mfrc522Transceiver<I2C>,
    ) -> Result<Self, Error<I2C::Error>> {
        transceiver
            .prepare_for_activation()
            .map_err(Error::Mfrc522)?;
        Self::activate_after_prepare(transceiver)
    }

    pub fn activate_after_prepare(
        transceiver: &'a mut Mfrc522Transceiver<I2C>,
    ) -> Result<Self, Error<I2C::Error>> {
        let activation = activation::wakeup(transceiver).map_err(Error::Activation)?;
        if !activation.sak.iso14443_4_compliant {
            return Err(Error::UnsupportedTag);
        }
        validate_uid(activation.uid.as_slice())?;

        let cid = Cid::new(0).ok_or(Error::InvalidCid)?;
        let (_, ats) =
            PcdSession::from_connect(transceiver, Fsdi::Fsd64, cid).map_err(Error::Protocol)?;

        transceiver.enable_hw_crc().map_err(Error::Mfrc522)?;

        let mut session = PcdSession::from_ats(&ats, None, true);
        session.set_fsc(core::cmp::min(ats.format.fsci.fsc(), 64));

        let fwt_ms = frame_wait_time_ms(&ats);
        transceiver.set_timeout_ms(fwt_ms).map_err(Error::Mfrc522)?;
        session.set_base_fwt_ms(fwt_ms);

        Ok(Self {
            transceiver,
            session,
            uid: activation.uid,
        })
    }

    pub fn uid(&self) -> &[u8] {
        self.uid.as_slice()
    }
}

impl<'a, I2C> Transport for Mfrc522Transport<'a, I2C>
where
    I2C: I2c,
    I2C::Error: Debug,
{
    type Error = Error<I2C::Error>;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Self::Data>, Self::Error> {
        let response = self
            .session
            .exchange(self.transceiver, apdu)
            .map_err(Error::Protocol)?;
        split_response(response.as_slice())
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        Ok(self.uid.clone())
    }
}

#[derive(Debug)]
pub enum Error<E> {
    Mfrc522(Mfrc522Error<E>),
    Activation(activation::ActivationError<Mfrc522Error<E>>),
    Protocol(PcdError<Mfrc522Error<E>>),
    InvalidCid,
    InvalidResponseLength(usize),
    InvalidUidLength(usize),
    UnsupportedTag,
}

impl<E: Debug> Display for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: Debug> core::error::Error for Error<E> {}

fn validate_uid<E>(uid: &[u8]) -> Result<(), Error<E>> {
    match uid.len() {
        4 | 7 => Ok(()),
        len => Err(Error::InvalidUidLength(len)),
    }
}

fn split_response<E>(response: &[u8]) -> Result<Response<Vec<u8>>, Error<E>> {
    if response.len() < 2 {
        return Err(Error::InvalidResponseLength(response.len()));
    }

    let split = response.len() - 2;
    Ok(Response {
        data: response[..split].to_vec(),
        sw1: response[split],
        sw2: response[split + 1],
    })
}

fn frame_wait_time_ms(ats: &Ats) -> u32 {
    let fwi = ats.tb.fwi.value();
    if fwi == 0 {
        5
    } else {
        let fwt_us = 302u64 * (1u64 << fwi);
        (fwt_us / 1000 + 10) as u32
    }
}
