#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    NotInitialized,
    NoCard,
    Communication,
    BufferOverflow,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotInitialized => write!(f, "PN532 device not initialized"),
            Error::NoCard => write!(f, "no card detected"),
            Error::Communication => write!(f, "communication error with PN532"),
            Error::BufferOverflow => write!(f, "buffer overflow"),
        }
    }
}

impl core::error::Error for Error {}

pub struct Pn532Device<PN532, RST> {
    pn532: PN532,
    rst_pin: RST,
    target_num: Option<u8>,
    initialized: bool,
    uid: Option<Vec<u8>>,
}

impl<PN532, RST> Pn532Device<PN532, RST> {
    pub fn raw_pn532(&self) -> &PN532 {
        &self.pn532
    }

    pub fn raw_pn532_mut(&mut self) -> &mut PN532 {
        &mut self.pn532
    }

    pub fn rst_pin(&self) -> &RST {
        &self.rst_pin
    }

    pub fn rst_pin_mut(&mut self) -> &mut RST {
        &mut self.rst_pin
    }
}

pub const PN532_BUF_SIZE: usize = 64;

fn max_response_len<const BUF: usize>() -> usize {
    BUF.saturating_sub(9)
}

pub trait BlockingMs {
    fn delay_ms(&mut self, ms: u32);
}

#[cfg(target_arch = "xtensa")]
pub use esp_idf_hal::delay::Delay as EspDelay;

#[cfg(target_arch = "xtensa")]
impl BlockingMs for EspDelay {
    fn delay_ms(&mut self, ms: u32) {
        esp_idf_hal::delay::Delay::delay_ms(self, ms);
    }
}

pub trait Pn532Ops {
    fn get_firmware_version(&mut self) -> Result<(u8, u8), Error>;
    fn configure_sam(&mut self) -> Result<(), Error>;
    fn inlist_passive_target(&mut self) -> Result<Option<(u8, Vec<u8>)>, Error>;
    fn in_data_exchange(&mut self, target_num: u8, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn in_release(&mut self, target_num: u8) -> Result<(), Error>;
}

impl<Pn532Hal, RST> Pn532Device<Pn532Hal, RST>
where
    Pn532Hal: Pn532Ops,
    RST: embedded_hal::digital::OutputPin,
{
    pub fn new(pn532: Pn532Hal, rst_pin: RST) -> Self {
        Self {
            pn532,
            rst_pin,
            target_num: None,
            initialized: false,
            uid: None,
        }
    }

    pub fn init_with_delay(&mut self, delay: &mut impl BlockingMs) -> Result<(), Error> {
        self.rst_pin.set_low().map_err(|_| Error::Communication)?;
        delay.delay_ms(100);
        self.rst_pin.set_high().map_err(|_| Error::Communication)?;
        delay.delay_ms(500);

        let (major, minor) = self.pn532.get_firmware_version()?;
        log::info!("PN532 firmware version: {major}.{minor}");
        self.pn532.configure_sam()?;
        self.initialized = true;
        Ok(())
    }

    #[cfg(target_arch = "xtensa")]
    pub fn init(&mut self) -> Result<(), Error> {
        self.init_with_delay(&mut EspDelay::new_default())
    }

    #[cfg(not(target_arch = "xtensa"))]
    pub fn init(&mut self) -> Result<(), Error> {
        Err(Error::NotInitialized)
    }

    pub fn detect_card(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        match self.pn532.inlist_passive_target() {
            Ok(Some((target_num, uid))) => {
                self.target_num = Some(target_num);
                self.uid = Some(uid);
                true
            }
            _ => {
                self.target_num = None;
                self.uid = None;
                false
            }
        }
    }

    pub fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }
        let target_num = self.target_num.ok_or(Error::NoCard)?;
        self.pn532.in_data_exchange(target_num, apdu)
    }

    pub fn release_card(&mut self) {
        if let Some(target_num) = self.target_num {
            let _ = self.pn532.in_release(target_num);
            self.target_num = None;
            self.uid = None;
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn card_present(&self) -> bool {
        self.target_num.is_some()
    }

    pub fn uid(&self) -> Option<&[u8]> {
        self.uid.as_deref()
    }
}

// The Pn532Ops blanket impl is NOT xtensa-specific (the generics are
// bus-agnostic pn532-crate traits) — de-gated 2026-10-20 so the STM32
// F469 port (bolty-stm32, docs/stm32-nfc-frontend-plan.md option B) can
// construct Pn532Device over any Interface. xtensa compilation is
// source-identical; downstream pins (ccid-firmware-rs rev-pins this
// repo) pick this up deliberately.
mod pn532_impl {
    use super::{Error, Pn532Ops, max_response_len};
    use alloc::vec::Vec;
    use core::time::Duration;

    use pn532::{
        CountDown, Interface, IntoDuration, Pn532, Request,
        requests::{BorrowedRequest, Command, SAMMode},
    };

    impl<IF, Timer, const BUF: usize> Pn532Ops for Pn532<IF, Timer, BUF>
    where
        IF: Interface,
        Timer: CountDown<Time = Duration>,
    {
        fn get_firmware_version(&mut self) -> Result<(u8, u8), Error> {
            let response = self
                .process(&Request::GET_FIRMWARE_VERSION, 4, 50.ms())
                .map_err(|_| Error::Communication)?;

            if response.len() < 4 || response.first().copied() != Some(0x32) {
                return Err(Error::Communication);
            }

            Ok((
                response.get(1).copied().unwrap_or(0),
                response.get(2).copied().unwrap_or(0),
            ))
        }

        fn configure_sam(&mut self) -> Result<(), Error> {
            self.process(
                &Request::sam_configuration(SAMMode::Normal, false),
                0,
                50.ms(),
            )
            .map_err(|_| Error::Communication)?;
            Ok(())
        }

        fn inlist_passive_target(&mut self) -> Result<Option<(u8, Vec<u8>)>, Error> {
            let max_resp = max_response_len::<BUF>().min(20);
            let response = self
                .process(&Request::INLIST_ONE_ISO_A_TARGET, max_resp, 1000.ms())
                .map_err(|_| Error::Communication)?;

            let targets_found = response.first().copied().unwrap_or(0);
            if targets_found == 0 {
                return Ok(None);
            }

            let target_num = response.get(1).copied().unwrap_or(0);
            let uid_len = response.get(5).copied().unwrap_or(0) as usize;
            let uid = response
                .get(6..6 + uid_len)
                .map(|s| s.to_vec())
                .unwrap_or_default();

            Ok(Some((target_num, uid)))
        }

        fn in_data_exchange(&mut self, target_num: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
            let mut buf = Vec::with_capacity(1 + data.len());
            buf.push(target_num);
            buf.extend_from_slice(data);

            let request = BorrowedRequest::new(Command::InDataExchange, &buf);
            let max_resp = max_response_len::<BUF>();

            let result = self
                .process(request, max_resp, 1000.ms())
                .map_err(|_| Error::Communication)?;

            let status = result.first().copied().unwrap_or(0xff);
            if status != 0x00 {
                return Err(Error::Communication);
            }

            Ok(result.get(1..).unwrap_or(&[]).to_vec())
        }

        fn in_release(&mut self, target_num: u8) -> Result<(), Error> {
            let _ = self.process(&Request::new(Command::InRelease, [target_num]), 0, 50.ms());
            Ok(())
        }
    }
}

#[cfg(not(target_arch = "xtensa"))]
mod stub_impl {
    use super::{Error, Pn532Ops};
    use alloc::vec::Vec;

    impl Pn532Ops for () {
        fn get_firmware_version(&mut self) -> Result<(u8, u8), Error> {
            Err(Error::NotInitialized)
        }
        fn configure_sam(&mut self) -> Result<(), Error> {
            Err(Error::NotInitialized)
        }
        fn inlist_passive_target(&mut self) -> Result<Option<(u8, Vec<u8>)>, Error> {
            Err(Error::NotInitialized)
        }
        fn in_data_exchange(&mut self, _target: u8, _data: &[u8]) -> Result<Vec<u8>, Error> {
            Err(Error::NotInitialized)
        }
        fn in_release(&mut self, _target: u8) -> Result<(), Error> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::convert::Infallible;

    /// Scripted Pn532Ops mock: outcomes are queueable so a test can
    /// replay a full chip session (the mock/hardware-divergence rule:
    /// model the transport's contract, incl. error paths).
    type InlistOutcome = Result<Option<(u8, Vec<u8>)>, Error>;

    #[derive(Default)]
    struct MockPn532 {
        firmware_results: VecDeque<Result<(u8, u8), Error>>,
        sam_results: VecDeque<Result<(), Error>>,
        inlist_results: VecDeque<InlistOutcome>,
        exchange_results: VecDeque<Result<Vec<u8>, Error>>,
        exchanged: Vec<(u8, Vec<u8>)>,
        released: Vec<u8>,
        inlist_calls: usize,
    }

    impl MockPn532 {
        fn happy() -> Self {
            let mut m = MockPn532::default();
            m.firmware_results.push_back(Ok((7, 0x16)));
            m.sam_results.push_back(Ok(()));
            m.inlist_results
                .push_back(Ok(Some((1, Vec::from([0x04, 0xA3, 0x94])))));
            m.exchange_results
                .push_back(Ok(Vec::from([0x00, 0x90, 0x00])));
            m
        }
    }

    impl Pn532Ops for MockPn532 {
        fn get_firmware_version(&mut self) -> Result<(u8, u8), Error> {
            self.firmware_results.pop_front().unwrap_or(Ok((7, 0x16)))
        }
        fn configure_sam(&mut self) -> Result<(), Error> {
            self.sam_results.pop_front().unwrap_or(Ok(()))
        }
        fn inlist_passive_target(&mut self) -> Result<Option<(u8, Vec<u8>)>, Error> {
            self.inlist_calls += 1;
            self.inlist_results.pop_front().unwrap_or(Ok(None))
        }
        fn in_data_exchange(&mut self, target_num: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
            self.exchanged.push((target_num, data.to_vec()));
            self.exchange_results.pop_front().unwrap_or(Ok(Vec::new()))
        }
        fn in_release(&mut self, target_num: u8) -> Result<(), Error> {
            self.released.push(target_num);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakePin {
        low: usize,
        high: usize,
    }

    impl embedded_hal::digital::ErrorType for FakePin {
        type Error = Infallible;
    }

    impl embedded_hal::digital::OutputPin for FakePin {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            self.low += 1;
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), Self::Error> {
            self.high += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeDelay {
        spent_ms: u32,
    }

    impl BlockingMs for FakeDelay {
        fn delay_ms(&mut self, ms: u32) {
            self.spent_ms += ms;
        }
    }

    #[test]
    fn new_device_is_uninitialized() {
        let dev = Pn532Device::new(MockPn532::default(), FakePin::default());
        assert!(!dev.is_initialized());
        assert!(!dev.card_present());
        assert!(dev.uid().is_none());
    }

    #[test]
    fn init_runs_reset_ladder_and_chip_setup() {
        let mut mock = MockPn532::happy();
        mock.inlist_results.clear();
        let mut dev = Pn532Device::new(mock, FakePin::default());
        let mut delay = FakeDelay::default();
        dev.init_with_delay(&mut delay).unwrap();
        assert!(dev.is_initialized());
        // RST low then high, with the documented settle windows.
        assert_eq!((dev.rst_pin().low, dev.rst_pin().high), (1, 1));
        assert_eq!(delay.spent_ms, 100 + 500);
        // init must not touch the field (no card detection side effects).
        assert_eq!(dev.raw_pn532().inlist_calls, 0);
    }

    #[test]
    fn init_propagates_firmware_version_error() {
        let mut mock = MockPn532::default();
        mock.firmware_results.push_back(Err(Error::Communication));
        let mut dev = Pn532Device::new(mock, FakePin::default());
        let mut delay = FakeDelay::default();
        assert!(matches!(
            dev.init_with_delay(&mut delay),
            Err(Error::Communication)
        ));
        assert!(!dev.is_initialized());
    }

    #[test]
    fn init_propagates_sam_configuration_error() {
        let mut mock = MockPn532::default();
        mock.firmware_results.push_back(Ok((7, 0x16)));
        mock.sam_results.push_back(Err(Error::Communication));
        let mut dev = Pn532Device::new(mock, FakePin::default());
        let mut delay = FakeDelay::default();
        assert!(matches!(
            dev.init_with_delay(&mut delay),
            Err(Error::Communication)
        ));
        assert!(!dev.is_initialized());
    }

    #[test]
    #[cfg(not(target_arch = "xtensa"))]
    fn non_xtensa_bare_init_reports_not_initialized() {
        // The RST/delay ladder needs a BlockingMs; the no-arg init() only
        // exists for xtensa. On host there is no default delay, so init()
        // must fail loudly instead of silently half-initializing.
        let mut dev = Pn532Device::new(MockPn532::happy(), FakePin::default());
        assert!(matches!(dev.init(), Err(Error::NotInitialized)));
    }

    #[test]
    fn detect_card_is_inert_until_initialized() {
        let mut mock = MockPn532::happy();
        mock.inlist_results.clear();
        let mut dev = Pn532Device::new(mock, FakePin::default());
        assert!(!dev.detect_card());
        assert_eq!(dev.raw_pn532().inlist_calls, 0);
    }

    #[test]
    fn detect_card_captures_target_and_uid() {
        let mut dev = Pn532Device::new(MockPn532::happy(), FakePin::default());
        let mut delay = FakeDelay::default();
        dev.init_with_delay(&mut delay).unwrap();
        assert!(dev.detect_card());
        assert!(dev.card_present());
        assert_eq!(dev.uid(), Some(&[0x04, 0xA3, 0x94][..]));
    }

    #[test]
    fn detect_card_none_clears_previous_state() {
        let mut mock = MockPn532::happy();
        mock.inlist_results.push_back(Ok(None));
        let mut dev = Pn532Device::new(mock, FakePin::default());
        let mut delay = FakeDelay::default();
        dev.init_with_delay(&mut delay).unwrap();
        assert!(dev.detect_card());
        assert!(!dev.detect_card());
        assert!(!dev.card_present());
        assert!(dev.uid().is_none());
    }

    #[test]
    fn exchange_apdu_requires_initialization() {
        let mut dev = Pn532Device::new(MockPn532::happy(), FakePin::default());
        assert!(matches!(
            dev.exchange_apdu(&[0x00]),
            Err(Error::NotInitialized)
        ));
    }

    #[test]
    fn exchange_apdu_requires_a_detected_card() {
        let mut mock = MockPn532::happy();
        mock.inlist_results.clear();
        let mut dev = Pn532Device::new(mock, FakePin::default());
        let mut delay = FakeDelay::default();
        dev.init_with_delay(&mut delay).unwrap();
        assert!(matches!(dev.exchange_apdu(&[0x00]), Err(Error::NoCard)));
    }

    #[test]
    fn exchange_apdu_routes_to_detected_target() {
        let mut mock = MockPn532::happy();
        mock.exchange_results.clear();
        mock.exchange_results.push_back(Ok(Vec::from([0x90, 0x00])));
        let mut dev = Pn532Device::new(mock, FakePin::default());
        let mut delay = FakeDelay::default();
        dev.init_with_delay(&mut delay).unwrap();
        dev.detect_card();
        let rsp = dev.exchange_apdu(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!(rsp, Vec::from([0x90, 0x00]));
        assert_eq!(
            dev.raw_pn532().exchanged,
            vec![(1, Vec::from([0x00, 0xA4, 0x04, 0x00]))]
        );
    }

    #[test]
    fn release_card_releases_target_and_clears_state() {
        let mut dev = Pn532Device::new(MockPn532::happy(), FakePin::default());
        let mut delay = FakeDelay::default();
        dev.init_with_delay(&mut delay).unwrap();
        dev.detect_card();
        dev.release_card();
        assert!(!dev.card_present());
        assert_eq!(dev.raw_pn532().released, vec![1]);
        // Releasing with no card must not talk to the chip.
        dev.release_card();
        assert_eq!(dev.raw_pn532().released.len(), 1);
    }
}
