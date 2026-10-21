#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

use ntag424::{Response, Transport};
use pn532_transport::Pn532Device;

pub struct Pn532Transport<PN532, RST> {
    device: Pn532Device<PN532, RST>,
    uid: Option<Vec<u8>>,
}

impl<PN532, RST> Pn532Transport<PN532, RST>
where
    PN532: pn532_transport::Pn532Ops,
    RST: embedded_hal::digital::OutputPin,
{
    pub fn new(device: Pn532Device<PN532, RST>) -> Self {
        Self { device, uid: None }
    }

    /// Convenience activation using the target's default delay — only
    /// usable where `Pn532Device::init` has an implementation (xtensa
    /// today). Non-xtensa callers (host tests, the STM32 port) must use
    /// [`Self::activate_with_delay`].
    pub fn activate(&mut self) -> Result<(), Error> {
        if !self.device.is_initialized() {
            self.device.init().map_err(Error::Device)?;
        }
        self.finish_activation()
    }

    /// Delay-injected activation: runs the RST settle ladder + chip init
    /// with the caller's BlockingMs, then detects a card. Portable entry
    /// point (gap found by the 2026-10-19 loopback tests: activate()
    /// alone can never work where init() has no delay implementation).
    pub fn activate_with_delay(
        &mut self,
        delay: &mut impl pn532_transport::BlockingMs,
    ) -> Result<(), Error> {
        if !self.device.is_initialized() {
            self.device.init_with_delay(delay).map_err(Error::Device)?;
        }
        self.finish_activation()
    }

    fn finish_activation(&mut self) -> Result<(), Error> {
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

impl<PN532, RST> Transport for Pn532Transport<PN532, RST>
where
    PN532: pn532_transport::Pn532Ops,
    RST: embedded_hal::digital::OutputPin,
{
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
    use alloc::collections::VecDeque;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use pn532_transport::{BlockingMs, Error as DeviceError, Pn532Ops};

    type InlistOutcome = Result<Option<(u8, Vec<u8>)>, DeviceError>;

    fn block_on<F: Future>(mut fut: F) -> F::Output {
        // Same minimal no_std block_on the app crate uses.
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: the future is not moved and lives until polled to done.
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    struct MockPn532 {
        firmware_results: VecDeque<Result<(u8, u8), DeviceError>>,
        sam_results: VecDeque<Result<(), DeviceError>>,
        inlist_results: VecDeque<InlistOutcome>,
        exchange_results: VecDeque<Result<Vec<u8>, DeviceError>>,
        released: Vec<u8>,
    }

    impl MockPn532 {
        fn with_card() -> Self {
            let mut m = MockPn532 {
                firmware_results: VecDeque::new(),
                sam_results: VecDeque::new(),
                inlist_results: VecDeque::new(),
                exchange_results: VecDeque::new(),
                released: Vec::new(),
            };
            m.firmware_results.push_back(Ok((7, 0x16)));
            m.sam_results.push_back(Ok(()));
            m.inlist_results
                .push_back(Ok(Some((1, Vec::from([0x04, 0xC4, 0x74])))));
            m
        }
    }

    impl Pn532Ops for MockPn532 {
        fn get_firmware_version(&mut self) -> Result<(u8, u8), DeviceError> {
            self.firmware_results.pop_front().unwrap_or(Ok((7, 0x16)))
        }
        fn configure_sam(&mut self) -> Result<(), DeviceError> {
            self.sam_results.pop_front().unwrap_or(Ok(()))
        }
        fn inlist_passive_target(&mut self) -> Result<Option<(u8, Vec<u8>)>, DeviceError> {
            self.inlist_results.pop_front().unwrap_or(Ok(None))
        }
        fn in_data_exchange(
            &mut self,
            _target_num: u8,
            _data: &[u8],
        ) -> Result<Vec<u8>, DeviceError> {
            self.exchange_results
                .pop_front()
                .unwrap_or(Ok(Vec::from([0x90, 0x00])))
        }
        fn in_release(&mut self, target_num: u8) -> Result<(), DeviceError> {
            self.released.push(target_num);
            Ok(())
        }
    }

    struct FakePin;
    impl embedded_hal::digital::ErrorType for FakePin {
        type Error = Infallible;
    }
    impl embedded_hal::digital::OutputPin for FakePin {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct FakeDelay;
    impl BlockingMs for FakeDelay {
        fn delay_ms(&mut self, _ms: u32) {}
    }

    fn transport(mock: MockPn532) -> Pn532Transport<MockPn532, FakePin> {
        Pn532Transport::new(pn532_transport::Pn532Device::new(mock, FakePin))
    }

    #[test]
    fn activate_initializes_device_and_captures_uid() {
        let mut t = transport(MockPn532::with_card());
        t.activate_with_delay(&mut FakeDelay).unwrap();
        assert_eq!(t.device().uid(), Some(&[0x04, 0xC4, 0x74][..]));
    }

    #[test]
    fn activate_reports_no_card_when_field_empty() {
        let mut mock = MockPn532::with_card();
        mock.inlist_results.clear();
        let mut t = transport(mock);
        assert!(matches!(
            t.activate_with_delay(&mut FakeDelay),
            Err(Error::NoCard)
        ));
    }

    #[test]
    #[cfg(not(target_arch = "xtensa"))]
    fn bare_activate_is_unportable_and_fails_loudly() {
        // Guards the API gap the loopback tests found: activate() without
        // a delay only exists on xtensa — on host (and, until ported, the
        // STM32) it must error instead of half-activating.
        let mut t = transport(MockPn532::with_card());
        assert!(matches!(
            t.activate(),
            Err(Error::Device(DeviceError::NotInitialized))
        ));
        assert!(!t.device().is_initialized());
    }

    #[test]
    fn transmit_splits_status_word_from_data() {
        let mut t = transport(MockPn532::with_card());
        t.activate_with_delay(&mut FakeDelay).unwrap();
        t.device_mut()
            .raw_pn532_mut()
            .exchange_results
            .push_back(Ok(Vec::from([0x6F, 0x10, 0x90, 0x00])));
        let rsp = block_on(t.transmit(&[0x00, 0xA4, 0x04, 0x00])).unwrap();
        assert_eq!(rsp.data, Vec::from([0x6F, 0x10]));
        assert_eq!((rsp.sw1, rsp.sw2), (0x90, 0x00));
    }

    #[test]
    fn transmit_rejects_short_response() {
        let mut t = transport(MockPn532::with_card());
        t.activate_with_delay(&mut FakeDelay).unwrap();
        t.device_mut()
            .raw_pn532_mut()
            .exchange_results
            .push_back(Ok(Vec::from([0x90])));
        assert!(matches!(
            block_on(t.transmit(&[0x00])),
            Err(Error::InvalidResponseLength(1))
        ));
    }

    #[test]
    fn transmit_maps_device_errors() {
        let mut t = transport(MockPn532::with_card());
        t.activate_with_delay(&mut FakeDelay).unwrap();
        t.device_mut()
            .raw_pn532_mut()
            .exchange_results
            .push_back(Err(DeviceError::Communication));
        assert!(matches!(
            block_on(t.transmit(&[0x00])),
            Err(Error::Device(DeviceError::Communication))
        ));
    }

    #[test]
    fn release_returns_the_card_to_the_chip() {
        let mut t = transport(MockPn532::with_card());
        t.activate_with_delay(&mut FakeDelay).unwrap();
        t.release();
        assert_eq!(t.device().raw_pn532().released, vec![1]);
        assert!(!t.device().card_present());
    }

    #[test]
    fn get_uid_after_activate_matches_detection() {
        let mut t = transport(MockPn532::with_card());
        t.activate_with_delay(&mut FakeDelay).unwrap();
        let uid = block_on(t.get_uid()).unwrap();
        assert_eq!(uid, Vec::from([0x04, 0xC4, 0x74]));
    }
}
