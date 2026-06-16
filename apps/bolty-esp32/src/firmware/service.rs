use std::vec::Vec;

use crate::service::{ServiceStatus, WorkflowResult};
use bolty_core::{
    assessment::{CardAssessment, CardState},
    config::BoltyConfig,
    secret::CardKeys,
};
use bolty_mfrc522::{Mfrc522Transceiver, Mfrc522Transport};

use crate::block_on;
#[cfg(feature = "rest")]
use crate::rest::RestBoltyService;

use super::utils::{copy_uid7, nfc_unavailable_result, scan_i2c_bus, uid_storage_from_fixed};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiagnoseState {
    Blank,
    Provisioned,
    AuthDelay,
    Inconsistent,
}

pub(super) struct PiccResult {
    pub(super) inspect: bolty_ntag::SafeInspectResult,
    pub(super) keys_loaded: bool,
    pub(super) keys_confirmed: bool,
    pub(super) uid_match: Option<bool>,
}

pub(super) struct DiagnoseResult {
    pub(super) inspect: bolty_ntag::SafeInspectResult,
    pub(super) zero_key_attempted: bool,
    pub(super) zero_key_auth_ok: bool,
    pub(super) state: DiagnoseState,
}

pub(super) struct Esp32BoltyService<I2C>
where
    I2C: embedded_hal::i2c::I2c,
{
    transceiver: Option<Mfrc522Transceiver<I2C>>,
    raw_i2c: Option<I2C>,
    last_i2c_scan: Vec<u8>,
    pub(super) current_config: BoltyConfig,
    pub(super) keys: Option<CardKeys>,
    pub(super) authenticated_key0: Option<[u8; 16]>,
    pub(super) last_card: CardAssessment,
    pub(super) status: ServiceStatus,
    display_init_ok: bool,
    i2c_baudrate: u32,
}

pub(super) struct HwInfo {
    pub(super) display_init_ok: bool,
    pub(super) i2c_baudrate: u32,
    pub(super) last_i2c_scan: Vec<u8>,
    pub(super) nfc_ready: bool,
}

impl<I2C> Esp32BoltyService<I2C>
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    pub(super) fn new(
        transceiver: Option<Mfrc522Transceiver<I2C>>,
        raw_i2c: Option<I2C>,
        last_i2c_scan: Vec<u8>,
        current_config: BoltyConfig,
        display_init_ok: bool,
        i2c_baudrate: u32,
    ) -> Self {
        let nfc_ready = transceiver.is_some();
        let mut service = Self {
            transceiver,
            raw_i2c,
            last_i2c_scan,
            current_config,
            keys: None,
            authenticated_key0: None,
            last_card: CardAssessment::default(),
            status: ServiceStatus {
                last_uid: None,
                nfc_ready,
                lnurl: None,
            },
            display_init_ok,
            i2c_baudrate,
        };
        service.sync_config();
        service
    }

    pub(super) fn sync_from(&mut self, config: &BoltyConfig) {
        self.current_config = config.clone();
        self.sync_config();
    }

    pub(super) fn sync_config(&mut self) {
        self.status.lnurl = self.current_config.lnurl.clone();
        self.status.nfc_ready = self.transceiver.is_some();
        if self.keys.is_none() {
            self.keys = self.current_config.pending_keys.clone();
        }
        if let Some(ref lnurl) = self.current_config.lnurl {
            super::nvs::save_lnurl(lnurl.as_str());
        }
    }

    pub(super) fn nfc_available(&self) -> bool {
        self.transceiver.is_some()
    }

    /// Lightweight card-presence check via ISO 14443A detection only.
    ///
    /// Unlike `check_blank()`, this does NOT authenticate and therefore
    /// does not increment the NTAG424's failed-authentication counter.
    /// Use this for polling loops to avoid bricking cards with auth spam.
    pub(super) fn card_present(&mut self) -> bool {
        match self.activate_transport() {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Lightweight unauthenticated card poll for the main loop.
    ///
    /// Detects card presence, reads UID, and classifies state using
    /// unauthenticated reads only (file settings, NDEF). NEVER sends
    /// AuthenticateAES — this is safe to call every poll cycle without
    /// incrementing the NTAG424's SeqFailCtr or TotFailCtr.
    ///
    /// Returns `None` if no card is present.
    pub(super) fn poll_safe(&mut self) -> Option<CardAssessment> {
        let mut transport = self.activate_transport().ok()?;
        let _uid = copy_uid7(transport.uid())?;

        // Unauthenticated reads only — no AES authentication APDUs sent.
        let inspect = block_on(bolty_ntag::safe_inspect(&mut transport, None, None)).ok()?;

        let state = if let Some(ref settings) = inspect.file_settings {
            if settings.sdm.is_some()
                && settings
                    .sdm
                    .as_ref()
                    .map(|sdm| {
                        !matches!(sdm.picc_data(), bolty_ntag::PiccData::None)
                            || sdm.file_read().is_some()
                    })
                    .unwrap_or(false)
            {
                CardState::Provisioned(0)
            } else {
                CardState::Blank
            }
        } else {
            CardState::Unknown
        };

        let assessment = CardAssessment {
            present: true,
            uid: uid_storage_from_fixed(&inspect.uid),
            uid_len: 7,
            state,
            ..CardAssessment::default()
        };

        self.status.last_uid = Some(inspect.uid);
        self.status.nfc_ready = true;
        self.last_card = assessment.clone();

        Some(assessment)
    }

    pub(super) fn i2c_scan(&mut self) -> Vec<u8> {
        if let Some(i2c) = self.raw_i2c.as_mut() {
            self.last_i2c_scan = scan_i2c_bus(i2c);
        }
        self.last_i2c_scan.clone()
    }

    pub(super) fn get_hwinfo(&self) -> HwInfo {
        HwInfo {
            display_init_ok: self.display_init_ok,
            i2c_baudrate: self.i2c_baudrate,
            last_i2c_scan: self.last_i2c_scan.clone(),
            nfc_ready: self.status.nfc_ready,
        }
    }

    pub(super) fn activate_transport(
        &mut self,
    ) -> Result<Mfrc522Transport<'_, I2C>, WorkflowResult> {
        let Some(transceiver) = self.transceiver.as_mut() else {
            self.status.nfc_ready = false;
            self.last_card = CardAssessment::default();
            return Err(nfc_unavailable_result());
        };

        Mfrc522Transport::activate(transceiver).map_err(|_| {
            self.status.nfc_ready = true;
            self.last_card = CardAssessment::default();
            WorkflowResult::CardNotPresent
        })
    }
}

#[cfg(feature = "rest")]
impl<I2C> RestBoltyService for Esp32BoltyService<I2C>
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    fn sync_from(&mut self, config: &BoltyConfig) {
        Self::sync_from(self, config);
    }
}
