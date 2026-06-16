use crate::block_on;
use crate::service::{BoltyService, ServiceStatus, WorkflowResult};
use bolty_core::{
    assessment::{CardAssessment, CardState},
    config::IssuerConfig,
    derivation::BoltcardDeterministicDeriver,
    issuer::assess_card,
    secret::{AesKey, CardKeys},
    uid::CardUid,
};
use ntag424::KeyNumber;

use super::gen_rnd_a;
use super::service::{DiagnoseResult, DiagnoseState, Esp32BoltyService, PiccResult};
use super::utils::{
    card_keys_to_keyset, copy_lnurl, copy_uid7, looks_factory_default, map_ntag_error,
    uid_storage_from_fixed, workflow_error,
};

impl<I2C> Esp32BoltyService<I2C>
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    fn inspect_with_key(&mut self, key: &[u8; 16]) -> Result<CardAssessment, WorkflowResult> {
        let mut transport = self.activate_transport()?;
        let uid =
            copy_uid7(transport.uid()).ok_or_else(|| workflow_error("unsupported uid length"))?;
        let key_versions = block_on(bolty_ntag::check_key_versions(
            &mut transport,
            key,
            gen_rnd_a(),
        ))
        .map_err(|err| map_ntag_error(&err))?;

        let issuer = self
            .current_config
            .pending_issuer
            .as_ref()
            .map(|issuer_key| IssuerConfig {
                name: self.current_config.issuer_name.clone(),
                issuer_key: issuer_key.clone(),
                ..IssuerConfig::default()
            });
        let issuers = issuer.as_ref().map(core::slice::from_ref).unwrap_or(&[]);

        let assessment = assess_card(bolty_core::uid::CardUid::from(uid), key_versions, issuers);
        self.authenticated_key0 = Some(*key);
        self.last_card = assessment.clone();
        self.status.last_uid = Some(uid);
        self.status.nfc_ready = true;

        Ok(assessment)
    }

    pub(super) fn picc(&mut self) -> Result<PiccResult, WorkflowResult> {
        let keys = self.keys.clone();
        let keys_loaded = keys.is_some();
        let k1 = keys.as_ref().map(|keys| keys.k1.as_bytes());
        let k2 = keys.as_ref().map(|keys| keys.k2.as_bytes());
        let k0 = keys.as_ref().map(|keys| *keys.k0.as_bytes());

        let mut transport = self.activate_transport()?;
        let inspect = block_on(bolty_ntag::safe_inspect(&mut transport, k1, k2))
            .map_err(|err| map_ntag_error(&err))?;

        let uid_match = inspect
            .sdm_verification
            .as_ref()
            .and_then(|verification| verification.uid.map(|uid| uid == inspect.uid));
        let keys_confirmed = inspect.sdm_verification.is_some() && keys_loaded;

        self.status.last_uid = Some(inspect.uid);
        self.status.nfc_ready = true;
        self.last_card = CardAssessment {
            state: if keys_confirmed {
                CardState::Provisioned(0)
            } else {
                CardState::Unknown
            },
            present: true,
            uid: uid_storage_from_fixed(&inspect.uid),
            uid_len: 7,
            has_ndef: inspect.ndef_bytes.is_some(),
            ..CardAssessment::default()
        };

        if let Some(k0) = k0.filter(|_| keys_confirmed) {
            self.authenticated_key0 = Some(k0);
        }

        Ok(PiccResult {
            inspect,
            keys_loaded,
            keys_confirmed,
            uid_match,
        })
    }

    pub(super) fn diagnose(&mut self) -> Result<DiagnoseResult, WorkflowResult> {
        let mut transport = self.activate_transport()?;
        let inspect = block_on(bolty_ntag::safe_inspect(&mut transport, None, None))
            .map_err(|err| map_ntag_error(&err))?;

        let factory_like = looks_factory_default(inspect.file_settings.as_ref());
        let mut zero_key_attempted = false;
        let mut zero_key_auth_ok = false;
        let mut state = if inspect
            .file_settings
            .as_ref()
            .and_then(|settings| settings.sdm)
            .is_some()
        {
            DiagnoseState::Provisioned
        } else {
            DiagnoseState::Inconsistent
        };

        if factory_like {
            zero_key_attempted = true;
            match block_on(ntag424::Session::default().authenticate_aes(
                &mut transport,
                KeyNumber::Key0,
                &bolty_ntag::FACTORY_KEY,
                gen_rnd_a(),
            )) {
                Ok(_) => {
                    zero_key_auth_ok = true;
                    state = DiagnoseState::Blank;
                }
                Err(ntag424::SessionError::ErrorResponse(
                    ntag424::types::ResponseStatus::AuthenticationDelay,
                )) => {
                    state = DiagnoseState::AuthDelay;
                }
                Err(_) => {
                    state = DiagnoseState::Inconsistent;
                }
            }
        } else if inspect.file_settings.is_some() || inspect.ndef_bytes.is_some() {
            state = DiagnoseState::Provisioned;
        }

        self.status.last_uid = Some(inspect.uid);
        self.status.nfc_ready = true;
        self.last_card = CardAssessment {
            state: match state {
                DiagnoseState::Blank => CardState::Blank,
                DiagnoseState::Provisioned => CardState::Provisioned(0),
                DiagnoseState::AuthDelay | DiagnoseState::Inconsistent => CardState::Unknown,
            },
            present: true,
            uid: uid_storage_from_fixed(&inspect.uid),
            uid_len: 7,
            has_ndef: inspect.ndef_bytes.is_some(),
            zero_key_auth_ok,
            ..CardAssessment::default()
        };

        Ok(DiagnoseResult {
            inspect,
            zero_key_attempted,
            zero_key_auth_ok,
            state,
        })
    }
}

impl<I2C> BoltyService for Esp32BoltyService<I2C>
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    fn burn(
        &mut self,
        issuer: Option<&AesKey>,
        keys: Option<&CardKeys>,
        lnurl: &str,
    ) -> WorkflowResult {
        let key_version = IssuerConfig::default().key_version;

        let mut transport = match self.activate_transport() {
            Ok(transport) => transport,
            Err(err) => return err,
        };

        let card_keys = if let Some(issuer_key) = issuer {
            let uid_fixed = match copy_uid7(transport.uid()) {
                Some(uid) => uid,
                None => return workflow_error("unsupported uid length"),
            };
            let derived = BoltcardDeterministicDeriver::derive_keys(
                issuer_key.as_bytes(),
                CardUid::from(uid_fixed),
                key_version as u32,
            );
            CardKeys {
                k0: derived.k0.clone(),
                k1: derived.k1.clone(),
                k2: derived.k2.clone(),
                k3: derived.k3.clone(),
                k4: derived.k4.clone(),
            }
        } else if let Some(keys) = keys {
            keys.clone()
        } else {
            return workflow_error("missing keys or issuer");
        };

        let keyset = card_keys_to_keyset(&card_keys);

        use ntag424::types::ResponseStatus;

        let (current_key, previous_keys) =
            match block_on(ntag424::Session::default().authenticate_aes(
                &mut transport,
                KeyNumber::Key0,
                &bolty_ntag::FACTORY_KEY,
                gen_rnd_a(),
            )) {
                Ok(_) => (bolty_ntag::FACTORY_KEY, [bolty_ntag::FACTORY_KEY; 5]),
                Err(ntag424::SessionError::ErrorResponse(ResponseStatus::AuthenticationDelay)) => {
                    return WorkflowResult::AuthDelay;
                }
                Err(_) => {
                    let derived_result = block_on(ntag424::Session::default().authenticate_aes(
                        &mut transport,
                        KeyNumber::Key0,
                        &keyset[0],
                        gen_rnd_a(),
                    ));
                    match derived_result {
                        Ok(_) => (keyset[0], keyset),
                        Err(ntag424::SessionError::ErrorResponse(
                            ResponseStatus::AuthenticationDelay,
                        )) => return WorkflowResult::AuthDelay,
                        Err(_) => return WorkflowResult::AuthFailed,
                    }
                }
            };

        let params = bolty_ntag::BurnParams {
            lnurl,
            keys: keyset,
            key_version,
            current_key,
            previous_keys,
        };

        match block_on(bolty_ntag::burn(&mut transport, &params, gen_rnd_a())) {
            Ok(result) => {
                self.status.last_uid = Some(result.uid);
                self.status.nfc_ready = true;
                self.keys = Some(card_keys.clone());
                self.authenticated_key0 = Some(*card_keys.k0.as_bytes());
                self.current_config.pending_keys = Some(card_keys);
                self.current_config.lnurl = copy_lnurl(lnurl);
                self.sync_config();
                WorkflowResult::Success
            }
            Err(err) => map_ntag_error(&err),
        }
    }

    fn wipe(&mut self, issuer: Option<&AesKey>, keys: Option<&CardKeys>) -> WorkflowResult {
        let force_unsafe = self.current_config.force_unsafe;
        let mut transport = match self.activate_transport() {
            Ok(transport) => transport,
            Err(err) => return err,
        };

        let card_keys = if let Some(issuer_key) = issuer {
            let key_version = IssuerConfig::default().key_version;
            let uid_fixed = match copy_uid7(transport.uid()) {
                Some(uid) => uid,
                None => return workflow_error("unsupported uid length"),
            };
            let derived = BoltcardDeterministicDeriver::derive_keys(
                issuer_key.as_bytes(),
                CardUid::from(uid_fixed),
                key_version as u32,
            );
            CardKeys {
                k0: derived.k0.clone(),
                k1: derived.k1.clone(),
                k2: derived.k2.clone(),
                k3: derived.k3.clone(),
                k4: derived.k4.clone(),
            }
        } else if let Some(keys) = keys {
            keys.clone()
        } else {
            return WorkflowResult::WipeRefused;
        };

        log::info!("wipe: k0={:02X?}", card_keys.k0.as_bytes());

        if !force_unsafe {
            if let Ok(inspect) = block_on(bolty_ntag::safe_inspect(&mut transport, None, None)) {
                if looks_factory_default(inspect.file_settings.as_ref())
                    && inspect.ndef_bytes.is_none()
                {
                    return WorkflowResult::WipeRefused;
                }
            }
        }

        match block_on(bolty_ntag::wipe(
            &mut transport,
            &card_keys_to_keyset(&card_keys),
            gen_rnd_a(),
        )) {
            Ok(result) => {
                self.status.last_uid = Some(result.uid);
                self.status.nfc_ready = true;
                self.keys = None;
                self.authenticated_key0 = Some(bolty_ntag::FACTORY_KEY);
                self.last_card = CardAssessment {
                    state: CardState::Blank,
                    present: true,
                    uid: uid_storage_from_fixed(&result.uid),
                    uid_len: 7,
                    ..CardAssessment::default()
                };
                WorkflowResult::Success
            }
            Err(err) => map_ntag_error(&err),
        }
    }

    fn inspect(&mut self) -> Result<CardAssessment, WorkflowResult> {
        if let Some(keys) = self.keys.clone() {
            match self.inspect_with_key(keys.k0.as_bytes()) {
                Ok(assessment) => return Ok(assessment),
                Err(WorkflowResult::AuthFailed) | Err(WorkflowResult::CardNotPresent) => {}
                Err(WorkflowResult::AuthDelay) => return Err(WorkflowResult::AuthDelay),
                Err(err) => return Err(err),
            }
        }

        self.inspect_with_key(&bolty_ntag::FACTORY_KEY)
    }

    fn check_blank(&mut self) -> WorkflowResult {
        match self.inspect() {
            Ok(assessment) if assessment.state == CardState::Blank => WorkflowResult::Success,
            Ok(_) => workflow_error("card not blank"),
            Err(err) => err,
        }
    }

    fn get_status(&self) -> ServiceStatus {
        self.status.clone()
    }
}
