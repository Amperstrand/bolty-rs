//! MFRC522 NFC frontend transport for NTAG424 card communication.
//!
//! Implements the `ntag424::Transport` trait over I²C-connected MFRC522
//! hardware, handling ISO/IEC 14443-4 Type A activation, ISO-DEP frame
//! transceive with hardware CRC, and APDU-level exchange with the card.
//!
//! `#![no_std]`-compatible (uses `alloc`).
//!
//! Key types: `Mfrc522Transceiver` (re-exported from `mfrc522-pcd`),
//! `Mfrc522Transport`, `Error`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

use embedded_hal::i2c::I2c;
use iso14443::type_a::{
    Ats, Cid, Fsdi, activation,
    pcd::{PcdError, PcdSession},
};
use mfrc522::Error as Mfrc522Error;
use ntag424::{Response, Transport};

// Re-export the PCD-layer types from mfrc522-pcd so consumers of bolty-mfrc522
// see the same public API as before.
pub use mfrc522_pcd::{DEFAULT_I2C_ADDRESS, Mfrc522Transceiver};

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

/// SAFETY: response.len() >= 2 is checked above, so split = len-2 and
/// split+1 are always valid indices.
#[allow(clippy::indexing_slicing)]
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
