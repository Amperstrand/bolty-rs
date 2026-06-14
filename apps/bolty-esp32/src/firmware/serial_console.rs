use core::fmt::Write as _;

use bolty_core::assessment::CardAssessment;
use heapless::String;

use super::utils::{card_state_label, push_uid_hex};
use super::{SERIAL_FD_IN, SERIAL_FD_OUT};

pub(super) struct SerialConsole;

impl SerialConsole {
    pub(super) fn new() -> Self {
        let rc = unsafe {
            esp_idf_sys::fcntl(
                SERIAL_FD_IN,
                esp_idf_sys::F_SETFL as i32,
                esp_idf_sys::O_NONBLOCK as i32,
            )
        };
        if rc < 0 {
            log::warn!("failed to set stdin non-blocking: rc={rc}");
        }
        Self
    }

    pub(super) fn read_byte_nonblocking(&mut self) -> Option<u8> {
        let mut byte = 0u8;
        let read = unsafe { esp_idf_sys::read(SERIAL_FD_IN, (&mut byte as *mut u8).cast(), 1) };
        if read == 1 { Some(byte) } else { None }
    }

    pub(super) fn line(&mut self, line: &str) {
        self.write_all(line.as_bytes());
        self.write_all(b"\r\n");
    }

    pub(super) fn ok(&mut self, message: &str) {
        let mut line = String::<300>::new();
        let _ = write!(line, "[OK] {message}");
        self.line(line.as_str());
    }

    pub(super) fn fail(&mut self, message: &str) {
        let mut line = String::<300>::new();
        let _ = write!(line, "[FAIL] {message}");
        self.line(line.as_str());
    }

    pub(super) fn card(&mut self, assessment: &CardAssessment) {
        let mut uid = String::<32>::new();
        if let Some(raw_uid) = assessment.uid.as_ref() {
            let _ = push_uid_hex(&mut uid, &raw_uid[..assessment.uid_len as usize]);
        }

        let mut line = String::<96>::new();
        let _ = write!(
            line,
            "[CARD] uid={} state={}",
            uid.as_str(),
            card_state_label(assessment.state)
        );
        self.line(line.as_str());
    }

    pub(super) fn write_all(&mut self, bytes: &[u8]) {
        let mut written = 0usize;
        while written < bytes.len() {
            let rc = unsafe {
                esp_idf_sys::write(
                    SERIAL_FD_OUT,
                    bytes[written..].as_ptr().cast(),
                    bytes.len() - written,
                )
            };
            if rc <= 0 {
                break;
            }
            written += rc as usize;
        }
    }
}
