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

pub const PN532_BUF_SIZE: usize = 64;

#[cfg(target_arch = "xtensa")]
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

#[cfg(target_arch = "xtensa")]
mod xtensa_impl {
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
            let uid = if uid_len > 0 && 6 + uid_len <= response.len() {
                response[6..6 + uid_len].to_vec()
            } else {
                Vec::new()
            };

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
