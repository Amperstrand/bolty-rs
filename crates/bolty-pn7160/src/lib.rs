//! PN7160 NFC transport for bolty-rs: `ntag424::Transport` over the
//! `pn7160-nci` reader session. Follows the `bolty-pn532` pattern:
//! sync device calls wrapped in async trait methods, `activate()` /
//! `release()` bracketing the card session.
//!
//! The PN7160 handles ISO-DEP (ISO 14443-4) entirely in hardware — the
//! host exchanges NCI Data frames carrying raw APDUs, so no RATS/ATS
//! management is needed here (unlike MFRC522).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

use ntag424::{Response, Transport};
use pn7160_nci::driver::Pn7160Driver;
use pn7160_nci::Transport as NciTransport;

pub struct Pn7160Transport<T: NciTransport> {
    driver: Pn7160Driver<T>,
}

impl<T: NciTransport> Pn7160Transport<T> {
    pub fn new(transport: T) -> Self {
        Pn7160Transport {
            driver: Pn7160Driver::new(transport),
        }
    }

    pub fn activate(&mut self) -> Result<(), Error> {
        self.driver.init().map_err(Error::Driver)?;
        let mut atr = [0u8; 32];
        self.driver.power_on(&mut atr).map_err(Error::Driver)?;
        Ok(())
    }

    pub fn release(&mut self) {
        self.driver.power_off();
    }

    pub fn is_active(&self) -> bool {
        self.driver.session_active()
    }
}

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

impl<T: NciTransport> Transport for Pn7160Transport<T> {
    type Error = Error;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Vec<u8>>, Error> {
        let mut buf = [0u8; 255];
        let len = self
            .driver
            .transmit_apdu(apdu, &mut buf)
            .map_err(Error::Driver)?;
        split_response(buf.get(..len).unwrap_or(&[]))
    }

    async fn get_uid(&mut self) -> Result<Vec<u8>, Error> {
        let uid = self.driver.uid();
        if uid.is_empty() {
            return Err(Error::NoCard);
        }
        Ok(uid.to_vec())
    }
}

#[derive(Debug)]
pub enum Error {
    Driver(pn7160_nci::driver::Error),
    InvalidResponseLength(usize),
    NoCard,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Driver(e) => write!(f, "PN7160 driver error: {e:?}"),
            Error::InvalidResponseLength(len) => {
                write!(f, "invalid APDU response length: {len}")
            }
            Error::NoCard => write!(f, "no card in field"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use pn7160_nci::mock::MockTransport;
    use pn7160_nci::{
        DEACTIVATE_TYPE_IDLE, GID_CORE, GID_RF, MT_NTF, MT_RSP, NCI_INTERFACE_ISO_DEP,
        NCI_PROTOCOL_ISO_DEP, NTF_RF_DEACTIVATE, NTF_RF_DISCOVER, NTF_RF_INTF_ACTIVATED,
        OID_CORE_INIT, OID_CORE_RESET, OID_CORE_SET_CONFIG, OID_RF_DEACTIVATE, OID_RF_DISCOVER,
        OID_RF_DISCOVER_MAP, OID_RF_DISCOVER_SELECT, STATUS_OK,
    };

    fn script_full_session(t: &mut MockTransport) {
        t.push_reply(&[MT_RSP | GID_CORE, OID_CORE_RESET, 0x01, STATUS_OK]);
        t.push_notification(&[MT_NTF, OID_CORE_RESET, 0x01, 0x00]);
        t.push_reply(&[MT_RSP | GID_CORE, OID_CORE_INIT, 0x01, STATUS_OK]);
        t.push_reply(&[MT_RSP | GID_CORE, OID_CORE_SET_CONFIG, 0x01, STATUS_OK]);
        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DISCOVER_MAP, 0x01, STATUS_OK]);
        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DISCOVER, 0x01, STATUS_OK]);

        t.push_notification(&[
            MT_NTF | GID_RF,
            NTF_RF_DISCOVER,
            0x0D,
            0x01,
            NCI_PROTOCOL_ISO_DEP,
            0x00,
            0x08,
            0x44,
            0x00,
            0x04,
            0x04,
            0xA2,
            0xB3,
            0xC4,
            0x00,
            NCI_INTERFACE_ISO_DEP,
        ]);

        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DISCOVER_SELECT, 0x01, STATUS_OK]);
        t.push_notification(&[
            MT_NTF | GID_RF,
            NTF_RF_INTF_ACTIVATED,
            0x0A,
            0x01,
            NCI_INTERFACE_ISO_DEP,
            NCI_PROTOCOL_ISO_DEP,
            0x00,
            0xFF,
            0x04,
            0x75,
            0x77,
            0x81,
            0x02,
        ]);

        t.push_reply(&[0x00, 0x00, 0x02, 0x90, 0x00]);

        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DEACTIVATE, 0x01, STATUS_OK]);
        t.push_notification(&[
            MT_NTF | GID_RF,
            NTF_RF_DEACTIVATE,
            0x01,
            DEACTIVATE_TYPE_IDLE,
        ]);
    }

    #[test]
    fn full_session_activate_transmit_uid_release() {
        let mut t = MockTransport::new();
        script_full_session(&mut t);
        let mut transport = Pn7160Transport::new(t);

        transport.activate().expect("activate");
        assert!(transport.is_active());

        let rsp = futures_lite::future::block_on(transport.transmit(&[0x00, 0xA4, 0x04, 0x00]))
            .expect("transmit");
        assert_eq!(rsp.sw1, 0x90);
        assert_eq!(rsp.sw2, 0x00);
        assert!(rsp.data.is_empty());

        let uid = futures_lite::future::block_on(transport.get_uid()).expect("get_uid");
        assert_eq!(uid, vec![0x04, 0xA2, 0xB3, 0xC4]);

        transport.release();
        assert!(!transport.is_active());
    }

    #[test]
    fn transmit_without_card() {
        let mut transport = Pn7160Transport::new(MockTransport::new());
        let result = futures_lite::future::block_on(transport.transmit(&[0x00, 0xA4]));
        assert!(result.is_err());
    }

    #[test]
    fn get_uid_without_card() {
        let mut transport = Pn7160Transport::new(MockTransport::new());
        let result = futures_lite::future::block_on(transport.get_uid());
        assert!(result.is_err());
    }
}
