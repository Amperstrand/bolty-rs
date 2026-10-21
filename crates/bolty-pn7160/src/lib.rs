//! PN7160 NFC frontend transport for NTAG424 card communication.
//!
//! Implements the `ntag424::Transport` trait over the shared `pn7160-nci`
//! driver (homed in ccid-firmware-rs; consumed by rev per the fork-policy /
//! lesson B28 single-home rule). This is the bolty-side bridge only: bring-up
//! ladder, presence re-arm state machine, RF_DISCOVER lifecycle and ATR
//! synthesis all live upstream — bolty inherits every fix made there.
//!
//! `#![no_std]`-compatible (uses `alloc`).
//!
//! Key types: `Pn7160Transport`, `Error`.

#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

use ntag424::{Response, Transport};
use pn7160_nci::driver::Error as DriverError;

// B28 single-rev re-exports: consumers (bolty-esp32's board-nucula
// frontend) instantiate the ESP32 transport through THIS crate, so the
// ccid rev pin lives in exactly one manifest on the bolty side.
pub use pn7160_nci::board::{BoardPins, NUCULA};
pub use pn7160_nci::driver::Pn7160Driver;
#[cfg(feature = "esp")]
pub use pn7160_nci::esp_transport::{BusPins, EspPn7160Transport};

/// Maximum ISO-DEP I-block payload the NFCC will hand back for one
/// `transmit_apdu` (NCI DATA payload limit: 255 bytes + 3-byte header).
const APDU_RESPONSE_BUF: usize = 258;

pub struct Pn7160Transport<T: pn7160_nci::Transport> {
    driver: Pn7160Driver<T>,
    uid: Vec<u8>,
    atr: Vec<u8>,
}

impl<T: pn7160_nci::Transport> Pn7160Transport<T> {
    /// Bring the reader up (NCI ladder: CORE_RESET → CORE_INIT →
    /// RF_DISCOVER_MAP → RF_DISCOVER) and power on the first ISO-DEP tag
    /// found (bounded collect-wait lives upstream in the driver).
    pub fn activate(driver: Pn7160Driver<T>) -> Result<Self, Error> {
        let mut transport = Self {
            driver,
            uid: Vec::new(),
            atr: Vec::new(),
        };
        transport.driver.init().map_err(Error::Init)?;
        transport.power_on()?;
        Ok(transport)
    }

    /// Re-run discovery/power-on (e.g. after a card swap) on an
    /// already-initialized driver.
    pub fn power_on(&mut self) -> Result<(), Error> {
        let mut atr = [0u8; 33];
        let n = self.driver.power_on(&mut atr).map_err(Error::PowerOn)?;
        self.atr = atr
            .get(..n)
            .ok_or(Error::PowerOn(DriverError::BufferTooSmall))?
            .to_vec();
        self.uid = self.driver.uid().to_vec();
        Ok(())
    }

    /// Teardown back to DISCOVERY (RF_DEACTIVATE + RF_DISCOVER re-issue —
    /// the #125 lifecycle lives upstream) and return the driver.
    pub fn release(self) -> Pn7160Driver<T> {
        self.driver
    }

    pub fn uid(&self) -> &[u8] {
        &self.uid
    }

    pub fn atr(&self) -> &[u8] {
        &self.atr
    }

    pub fn session_active(&self) -> bool {
        self.driver.session_active()
    }
}

impl<T: pn7160_nci::Transport> Transport for Pn7160Transport<T> {
    type Error = Error;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Self::Data>, Self::Error> {
        let mut buf = [0u8; APDU_RESPONSE_BUF];
        let n = self
            .driver
            .transmit_apdu(apdu, &mut buf)
            .map_err(Error::Exchange)?;
        let rsp = buf
            .get(..n)
            .ok_or(Error::Exchange(DriverError::BufferTooSmall))?;
        split_response(rsp)
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        Ok(self.uid.clone())
    }
}

#[derive(Debug)]
pub enum Error {
    Init(DriverError),
    PowerOn(DriverError),
    Exchange(DriverError),
    InvalidResponseLength(usize),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for Error {}

/// SAFETY: response.len() >= 2 is checked above, so split = len-2 and
/// split+1 are always valid indices (same guarded pattern as bolty-mfrc522
/// and bolty-pn532).
#[allow(clippy::indexing_slicing)]
fn split_response(response: &[u8]) -> Result<Response<Vec<u8>>, Error> {
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

#[cfg(test)]
mod tests {

    /// Cross-crate response-split conformance contract (mirrored in
    /// bolty-mfrc522, bolty-pn532 and bolty-pn7160). The hoist was
    /// evaluated 2026-10-20: the only shared dependency is the
    /// rev-pinned ntag424 fork (frozen pending the owner's
    /// feed-vs-retire decision), so the 8-line split stays crate-local
    /// and THESE vectors are the drift guard — change one, change all
    /// three. Natural hoist home if the fork decision lands: a
    /// Response helper on the ntag424 fork itself.
    #[test]
    fn split_response_conformance() {
        // <2 bytes is always InvalidResponseLength(len)
        for short in [&[][..], &[0x6Fu8][..]] {
            match super::split_response(short) {
                Err(Error::InvalidResponseLength(n)) => assert_eq!(n, short.len()),
                Err(other) => panic!("expected InvalidResponseLength, got {other:?}"),
                Ok(_) => panic!("short input must not split"),
            }
        }
        // status-word-only responses
        for (rsp, sw) in [
            (&[0x90u8, 0x00][..], (0x90u8, 0x00u8)),
            (&[0x61, 0x00][..], (0x61, 0x00)),
            (&[0x67, 0x00][..], (0x67, 0x00)),
        ] {
            match super::split_response(rsp) {
                Ok(r) => {
                    assert!(r.data.is_empty());
                    assert_eq!((r.sw1, r.sw2), sw);
                }
                Err(e) => panic!("expected Ok, got {e:?}"),
            }
        }
        // data + status word, incl. SW-looking bytes inside data
        let cases: &[(&[u8], &[u8], u8, u8)] = &[
            (&[0x6F, 0x10, 0x90, 0x00], &[0x6F, 0x10], 0x90, 0x00),
            (&[0x00, 0xFF, 0x67, 0x00], &[0x00, 0xFF], 0x67, 0x00),
            (
                &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x90, 0x00],
                &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
                0x90,
                0x00,
            ),
        ];
        for (rsp, data, sw1, sw2) in cases {
            match super::split_response(rsp) {
                Ok(r) => {
                    assert_eq!(r.data.as_slice(), *data);
                    assert_eq!((r.sw1, r.sw2), (*sw1, *sw2));
                }
                Err(e) => panic!("expected Ok, got {e:?}"),
            }
        }
    }

    use super::*;
    use alloc::vec;
    use pn7160_nci::{
        Frame, GID_CORE, GID_RF, MT_NTF, MT_RSP, NCI_INTERFACE_ISO_DEP, NCI_PROTOCOL_ISO_DEP,
        NTF_RF_DISCOVER, NTF_RF_INTF_ACTIVATED, OID_CORE_INIT, OID_CORE_RESET, OID_RF_DISCOVER,
        OID_RF_DISCOVER_MAP, OID_RF_DISCOVER_SELECT, STATUS_OK, Transport as NciTransport,
    };
    use std::collections::VecDeque;

    /// Byte-for-byte mirrors pn7160-nci's own (cfg(test)-gated) mock: RSPs
    /// parked by `send` surface on the next `poll_frame`; `transact`
    /// consumes scripted replies; notifications drain separately.
    #[derive(Default)]
    struct ScriptedTransport {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
        notifications: VecDeque<Vec<u8>>,
        pending_rsp: Option<Vec<u8>>,
    }

    impl ScriptedTransport {
        fn push_reply(&mut self, raw: &[u8]) {
            self.replies.push_back(raw.to_vec());
        }

        fn push_notification(&mut self, raw: &[u8]) {
            self.notifications.push_back(raw.to_vec());
        }
    }

    impl NciTransport for ScriptedTransport {
        fn send(&mut self, cmd: &[u8]) -> bool {
            self.sent.push(cmd.to_vec());
            if let Some(raw) = self.replies.pop_front() {
                self.pending_rsp = Some(raw);
            }
            true
        }

        fn poll_frame(&mut self) -> Option<Frame> {
            if let Some(raw) = self.pending_rsp.take() {
                return Frame::decode(&raw);
            }
            self.notifications
                .pop_front()
                .and_then(|raw| Frame::decode(&raw))
        }

        fn transact(&mut self, cmd: &[u8]) -> Option<Frame> {
            self.sent.push(cmd.to_vec());
            self.replies.pop_front().and_then(|raw| Frame::decode(&raw))
        }

        fn drain(&mut self) -> Option<Frame> {
            self.notifications
                .pop_front()
                .and_then(|raw| Frame::decode(&raw))
        }
    }

    // Wire fixtures lifted from pn7160-nci's driver tests (the single home
    // of the byte-exact NCI layer).
    fn script_ladder(t: &mut ScriptedTransport) {
        t.push_reply(&[MT_RSP | GID_CORE, OID_CORE_RESET, 0x01, STATUS_OK]);
        t.push_notification(&[MT_NTF, OID_CORE_RESET, 0x01, 0x00]);
        t.push_reply(&[MT_RSP | GID_CORE, OID_CORE_INIT, 0x01, STATUS_OK]);
        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DISCOVER_MAP, 0x01, STATUS_OK]);
        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DISCOVER, 0x01, STATUS_OK]);
    }

    const TEST_ATS: [u8; 6] = [0x75, 0x77, 0x81, 0x02, 0x80, 0x73];

    fn script_discover_select_activate(t: &mut ScriptedTransport) {
        t.push_notification(&[
            MT_NTF | GID_RF,
            NTF_RF_DISCOVER,
            0x05,
            0x01,
            NCI_PROTOCOL_ISO_DEP,
            0x00,
            0x00,
            NCI_INTERFACE_ISO_DEP,
        ]);
        t.push_reply(&[MT_RSP | GID_RF, OID_RF_DISCOVER_SELECT, 0x01, STATUS_OK]);
        let mut ntf = vec![
            MT_NTF | GID_RF,
            NTF_RF_INTF_ACTIVATED,
            0x0C,
            0x01,
            NCI_INTERFACE_ISO_DEP,
            NCI_PROTOCOL_ISO_DEP,
            0x00,
            0xFF,
            TEST_ATS.len() as u8,
        ];
        ntf.extend_from_slice(&TEST_ATS);
        t.push_notification(&ntf);
    }

    fn script_apdu(t: &mut ScriptedTransport, response: &[u8]) {
        let mut data = vec![0x00, 0x00, response.len() as u8];
        data.extend_from_slice(response);
        t.push_reply(&data);
    }

    #[test]
    fn activate_runs_ladder_and_powers_on() {
        let mut t = ScriptedTransport::default();
        script_ladder(&mut t);
        script_discover_select_activate(&mut t);
        let transport = Pn7160Transport::activate(Pn7160Driver::new(t)).unwrap();
        assert!(transport.session_active());
        assert!(!transport.atr().is_empty());
    }

    #[test]
    fn transmit_splits_sw_from_data() {
        let mut t = ScriptedTransport::default();
        script_ladder(&mut t);
        script_discover_select_activate(&mut t);
        // NCI DATA payload = R-APDU body then SW1/SW2.
        script_apdu(&mut t, &[0xAA, 0xBB, 0x90, 0x00]);
        let mut transport = Pn7160Transport::activate(Pn7160Driver::new(t)).unwrap();

        let rsp = block_on(transport.transmit(&[0x00, 0xA4, 0x04, 0x00])).unwrap();
        assert_eq!(rsp.data, vec![0xAA, 0xBB]);
        assert_eq!((rsp.sw1, rsp.sw2), (0x90, 0x00));
    }

    #[test]
    fn transmit_without_session_maps_to_exchange_error() {
        let t = ScriptedTransport::default();
        let mut transport = Pn7160Transport {
            driver: Pn7160Driver::new(t),
            uid: Vec::new(),
            atr: Vec::new(),
        };
        let rsp = match block_on(transport.transmit(&[0x00])) {
            Err(e) => e,
            Ok(_) => panic!("transmit must fail without a powered session"),
        };
        assert!(matches!(rsp, Error::Exchange(DriverError::NoCard)));
    }

    #[test]
    fn get_uid_returns_cached_discovery_uid() {
        let mut t = ScriptedTransport::default();
        script_ladder(&mut t);
        script_discover_select_activate(&mut t);
        let mut transport = Pn7160Transport::activate(Pn7160Driver::new(t)).unwrap();
        let uid = block_on(transport.get_uid()).unwrap();
        assert_eq!(uid, transport.uid());
    }

    #[test]
    fn short_response_is_rejected() {
        assert!(matches!(
            split_response(&[0x90]),
            Err(Error::InvalidResponseLength(1))
        ));
        let ok = split_response(&[0x61, 0x00]).unwrap();
        assert!(ok.data.is_empty());
        assert_eq!((ok.sw1, ok.sw2), (0x61, 0x00));
    }

    /// House pattern (bolty-ntag tests/mock.rs): the ntag424 Transport
    /// methods never actually suspend on this path, so a single poll with a
    /// noop waker suffices.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("mock tests must not block"),
        }
    }
}
