#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

use ntag424::{Response, Transport};
use pn532_transport::Pn532Device;

pub struct Pn532Transport<PN532, RST> {
    device: Pn532Device<PN532, RST>,
    uid: Option<Vec<u8>>,
}

impl<PN532, RST> Pn532Transport<PN532, RST> {
    pub fn new(device: Pn532Device<PN532, RST>) -> Self {
        Self { device, uid: None }
    }

    pub fn activate(&mut self) -> Result<(), Error> {
        if !self.device.is_initialized() {
            self.device.init().map_err(Error::Device)?;
        }
        if !self.device.detect_card() {
            return Err(Error::NoCard);
        }
        self.uid = self.device.uid().map(|u| u.to_vec());
        Ok(())
    }

    pub fn release(&mut self) {
        self.device.release_card();
        self.uid = None;
    }

    pub fn device(&self) -> &Pn532Device<PN532, RST> {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut Pn532Device<PN532, RST> {
        &mut self.device
    }
}

impl<PN532, RST> Transport for Pn532Transport<PN532, RST> {
    type Error = Error;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Vec<u8>>, Error> {
        let response = self.device.exchange_apdu(apdu).map_err(Error::Device)?;
        split_response(&response)
    }

    async fn get_uid(&mut self) -> Result<Vec<u8>, Error> {
        self.uid.clone().ok_or(Error::NoCard)
    }
}

#[derive(Debug)]
pub enum Error {
    Device(pn532_transport::Error),
    InvalidResponseLength(usize),
    NoCard,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Device(e) => write!(f, "PN532 device error: {e}"),
            Error::InvalidResponseLength(len) => {
                write!(f, "invalid APDU response length: {len}")
            }
            Error::NoCard => write!(f, "no card detected"),
        }
    }
}

impl core::error::Error for Error {}

fn split_response(response: &[u8]) -> Result<Response<Vec<u8>>, Error> {
    if response.len() < 2 {
        return Err(Error::InvalidResponseLength(response.len()));
    }

    let split = response.len() - 2;
    let data = response.get(..split).unwrap_or(&[]).to_vec();
    let sw1 = response.get(split).copied().unwrap_or(0);
    let sw2 = response.get(split + 1).copied().unwrap_or(0);

    Ok(Response { data, sw1, sw2 })
}
