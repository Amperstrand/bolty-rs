#![no_std]

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

#[cfg(target_arch = "xtensa")]
mod xtensa {
    use super::{Error, Pn532Device};
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use core::time::Duration;

    use embedded_hal::digital::OutputPin;
    use esp_idf_hal::delay::Delay;
    use pn532::{
        CountDown, Interface, IntoDuration, Pn532, Request,
        requests::{BorrowedRequest, Command, SAMMode},
    };

    pub const PN532_BUF_SIZE: usize = 64;

    fn max_response_len<const BUF: usize>() -> usize {
        BUF.saturating_sub(9)
    }

    pub struct EspDelayTimer {
        deadline: Duration,
    }

    impl EspDelayTimer {
        pub fn new() -> Self {
            Self {
                deadline: Duration::ZERO,
            }
        }
    }

    impl CountDown for EspDelayTimer {
        type Time = Duration;

        fn start<T>(&mut self, count: T)
        where
            T: Into<Self::Time>,
        {
            self.deadline = count.into();
        }

        fn wait(&mut self) -> nb::Result<(), Infallible> {
            let ms = self.deadline.as_millis() as u32;
            if ms > 0 {
                Delay::new_default().delay_ms(ms);
                self.deadline = Duration::ZERO;
            }
            Ok(())
        }
    }

    impl<IF, Timer, RST, const BUF: usize> Pn532Device<Pn532<IF, Timer, BUF>, RST>
    where
        IF: Interface,
        Timer: CountDown,
        RST: OutputPin,
    {
        pub fn new(pn532: Pn532<IF, Timer, BUF>, rst_pin: RST) -> Self {
            Self {
                pn532,
                rst_pin,
                target_num: None,
                initialized: false,
                uid: None,
            }
        }

        pub fn init(&mut self) -> Result<(), Error> {
            self.hardware_reset()?;
            let (major, minor) = self.get_firmware_version()?;
            log::info!("PN532 firmware version: {major}.{minor}");
            self.configure_sam()?;
            self.initialized = true;
            Ok(())
        }

        pub fn detect_card(&mut self) -> bool {
            if !self.initialized {
                return false;
            }

            let max_resp = max_response_len::<BUF>().min(20);
            let result = self
                .pn532
                .process(&Request::INLIST_ONE_ISO_A_TARGET, max_resp, 1000.ms());

            match result {
                Ok(response) => {
                    let targets_found = response.first().copied().unwrap_or(0);
                    if targets_found > 0 {
                        self.target_num = response.get(1).copied();
                        let uid_len = response.get(5).copied().unwrap_or(0) as usize;
                        let start = 6;
                        let end = start + uid_len;
                        if uid_len > 0 && end <= response.len() {
                            self.uid = Some(response[start..end].to_vec());
                        } else {
                            self.uid = None;
                        }
                        true
                    } else {
                        self.target_num = None;
                        self.uid = None;
                        false
                    }
                }
                Err(_) => {
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

            let mut data = Vec::with_capacity(1 + apdu.len());
            data.push(target_num);
            data.extend_from_slice(apdu);

            let request = BorrowedRequest::new(Command::InDataExchange, &data);
            let max_resp = max_response_len::<BUF>();

            let result = self
                .pn532
                .process(request, max_resp, 1000.ms())
                .map_err(|_| Error::Communication)?;

            let status = result.first().copied().unwrap_or(0xff);
            if status != 0x00 {
                return Err(Error::Communication);
            }

            let payload = result.get(1..).unwrap_or(&[]);
            Ok(payload.to_vec())
        }

        pub fn release_card(&mut self) {
            if let Some(target_num) = self.target_num {
                let _ =
                    self.pn532
                        .process(&Request::new(Command::InRelease, [target_num]), 0, 50.ms());
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

        fn hardware_reset(&mut self) -> Result<(), Error> {
            self.rst_pin.set_low().map_err(|_| Error::Communication)?;
            Delay::new_default().delay_ms(100);
            self.rst_pin.set_high().map_err(|_| Error::Communication)?;
            Delay::new_default().delay_ms(500);
            Ok(())
        }

        fn get_firmware_version(&mut self) -> Result<(u8, u8), Error> {
            let response = self
                .pn532
                .process(&Request::GET_FIRMWARE_VERSION, 4, 50.ms())
                .map_err(|_| Error::Communication)?;

            if response.len() < 4 || response.first().copied() != Some(0x32) {
                return Err(Error::Communication);
            }

            let major = response.get(1).copied().unwrap_or(0);
            let minor = response.get(2).copied().unwrap_or(0);
            Ok((major, minor))
        }

        fn configure_sam(&mut self) -> Result<(), Error> {
            self.pn532
                .process(
                    &Request::sam_configuration(SAMMode::Normal, false),
                    0,
                    50.ms(),
                )
                .map_err(|_| Error::Communication)?;
            Ok(())
        }
    }
}

#[cfg(target_arch = "xtensa")]
pub use xtensa::*;

#[cfg(not(target_arch = "xtensa"))]
mod stub {
    use super::{Error, Pn532Device};
    use alloc::vec::Vec;

    impl<PN532, RST> Pn532Device<PN532, RST> {
        pub fn new(pn532: PN532, rst_pin: RST) -> Self {
            Self {
                pn532,
                rst_pin,
                target_num: None,
                initialized: false,
                uid: None,
            }
        }

        pub fn init(&mut self) -> Result<(), Error> {
            self.initialized = false;
            Err(Error::NotInitialized)
        }

        pub fn detect_card(&mut self) -> bool {
            self.target_num = None;
            self.uid = None;
            false
        }

        pub fn exchange_apdu(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, Error> {
            Err(Error::NotInitialized)
        }

        pub fn release_card(&mut self) {
            self.target_num = None;
            self.uid = None;
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
}
