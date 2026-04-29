use crate::{
    commands::Command,
    config::BoltyConfig,
    service::{BoltyService, WorkflowResult},
};

pub fn dispatch_command<S: BoltyService>(
    cmd: Command,
    service: &mut S,
    config: &mut BoltyConfig,
) -> WorkflowResult {
    match cmd {
        Command::Help
        | Command::Status
        | Command::Uid
        | Command::SetWifi { .. }
        | Command::WifiOff
        | Command::Ota { .. }
        | Command::Ndef
        | Command::Auth
        | Command::Ver
        | Command::KeyVer
        | Command::DummyBurn
        | Command::Reset
        | Command::Picc
        | Command::Diagnose
        | Command::DeriveKeys
        | Command::Issuer => WorkflowResult::Success,
        Command::SetKeys(keys) => {
            config.pending_keys = Some(keys);
            WorkflowResult::Success
        }
        Command::SetIssuer(issuer_key) => {
            config.pending_issuer = Some(issuer_key);
            WorkflowResult::Success
        }
        Command::SetUrl(url) => {
            config.lnurl = Some(url);
            WorkflowResult::Success
        }
        Command::Burn => {
            let Some(keys) = config.pending_keys.as_ref() else {
                return workflow_error("missing keys");
            };
            let Some(lnurl) = config.lnurl.as_ref() else {
                return workflow_error("missing lnurl");
            };
            service.burn(keys, lnurl.as_str())
        }
        Command::Wipe => service.wipe(config.pending_keys.as_ref()),
        Command::Inspect => match service.inspect() {
            Ok(_) => WorkflowResult::Success,
            Err(err) => err,
        },
        Command::Check => service.check_blank(),
    }
}

fn workflow_error(message: &str) -> WorkflowResult {
    let mut buffer = crate::config::MessageString::new();
    if buffer.push_str(message).is_err() {
        return WorkflowResult::Error(crate::config::MessageString::new());
    }
    WorkflowResult::Error(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assessment::CardAssessment,
        config::LnurlString,
        secret::{AesKey, CardKeys},
        service::ServiceStatus,
    };

    struct MockService {
        burn_calls: usize,
        wipe_calls: usize,
        inspect_calls: usize,
        check_calls: usize,
        last_burn_lnurl: Option<LnurlString>,
        last_wipe_had_keys: bool,
        inspect_result: Option<Result<CardAssessment, WorkflowResult>>,
        check_result: WorkflowResult,
        burn_result: WorkflowResult,
        wipe_result: WorkflowResult,
    }

    impl Default for MockService {
        fn default() -> Self {
            Self {
                burn_calls: 0,
                wipe_calls: 0,
                inspect_calls: 0,
                check_calls: 0,
                last_burn_lnurl: None,
                last_wipe_had_keys: false,
                inspect_result: None,
                check_result: WorkflowResult::Success,
                burn_result: WorkflowResult::Success,
                wipe_result: WorkflowResult::Success,
            }
        }
    }

    impl BoltyService for MockService {
        fn burn(&mut self, _keys: &CardKeys, lnurl: &str) -> WorkflowResult {
            self.burn_calls += 1;
            self.last_burn_lnurl = Some(lnurl_string(lnurl));
            self.burn_result.clone()
        }

        fn wipe(&mut self, expected_keys: Option<&CardKeys>) -> WorkflowResult {
            self.wipe_calls += 1;
            self.last_wipe_had_keys = expected_keys.is_some();
            self.wipe_result.clone()
        }

        fn inspect(&mut self) -> Result<CardAssessment, WorkflowResult> {
            self.inspect_calls += 1;
            self.inspect_result.clone().unwrap_or(Ok(CardAssessment::default()))
        }

        fn check_blank(&mut self) -> WorkflowResult {
            self.check_calls += 1;
            self.check_result.clone()
        }

        fn get_status(&self) -> ServiceStatus {
            ServiceStatus::default()
        }
    }

    #[test]
    fn set_commands_update_config() {
        let mut service = MockService::default();
        let mut config = BoltyConfig::default();

        let keys = CardKeys {
            k0: AesKey::new([0x00; 16]),
            k1: AesKey::new([0x11; 16]),
            k2: AesKey::new([0x22; 16]),
            k3: AesKey::new([0x33; 16]),
            k4: AesKey::new([0x44; 16]),
        };

        assert_eq!(dispatch_command(Command::SetKeys(keys.clone()), &mut service, &mut config), WorkflowResult::Success);
        assert_eq!(config.pending_keys, Some(keys));

        let issuer = AesKey::new([0xAA; 16]);
        assert_eq!(dispatch_command(Command::SetIssuer(issuer.clone()), &mut service, &mut config), WorkflowResult::Success);
        assert_eq!(config.pending_issuer, Some(issuer));

        let url = lnurl_string("https://example.com/pay");
        assert_eq!(dispatch_command(Command::SetUrl(url.clone()), &mut service, &mut config), WorkflowResult::Success);
        assert_eq!(config.lnurl, Some(url));
    }

    #[test]
    fn burn_requires_keys_and_lnurl() {
        let mut service = MockService::default();
        let mut config = BoltyConfig::default();

        assert_eq!(dispatch_command(Command::Burn, &mut service, &mut config), workflow_error("missing keys"));

        config.pending_keys = Some(CardKeys::zeroed());
        assert_eq!(dispatch_command(Command::Burn, &mut service, &mut config), workflow_error("missing lnurl"));
    }

    #[test]
    fn burn_and_wipe_delegate_to_service() {
        let mut service = MockService {
            burn_result: WorkflowResult::Success,
            wipe_result: WorkflowResult::WipeRefused,
            ..MockService::default()
        };
        let mut config = BoltyConfig {
            lnurl: Some(lnurl_string("https://example.com/pay")),
            issuer_name: None,
            pending_keys: Some(CardKeys::zeroed()),
            pending_issuer: None,
            rest_read_token: None,
            rest_write_token: None,
        };

        assert_eq!(dispatch_command(Command::Burn, &mut service, &mut config), WorkflowResult::Success);
        assert_eq!(service.burn_calls, 1);
        assert_eq!(service.last_burn_lnurl, Some(lnurl_string("https://example.com/pay")));

        assert_eq!(dispatch_command(Command::Wipe, &mut service, &mut config), WorkflowResult::WipeRefused);
        assert_eq!(service.wipe_calls, 1);
        assert!(service.last_wipe_had_keys);
    }

    #[test]
    fn inspect_and_check_wrap_service_results() {
        let mut service = MockService {
            inspect_result: Some(Err(WorkflowResult::AuthFailed)),
            check_result: WorkflowResult::CardNotPresent,
            ..MockService::default()
        };
        let mut config = BoltyConfig::default();

        assert_eq!(dispatch_command(Command::Inspect, &mut service, &mut config), WorkflowResult::AuthFailed);
        assert_eq!(dispatch_command(Command::Check, &mut service, &mut config), WorkflowResult::CardNotPresent);
        assert_eq!(service.inspect_calls, 1);
        assert_eq!(service.check_calls, 1);
    }

    #[test]
    fn stub_commands_return_success() {
        let mut service = MockService::default();
        let mut config = BoltyConfig::default();

        for command in [
            Command::Help,
            Command::Status,
            Command::Uid,
            Command::SetWifi {
                ssid: crate::config::WifiSsidString::new(),
                password: crate::config::WifiPasswordString::new(),
            },
            Command::WifiOff,
            Command::Ota {
                url: crate::config::UrlString::new(),
            },
            Command::Ndef,
            Command::Auth,
            Command::Ver,
            Command::KeyVer,
            Command::DummyBurn,
            Command::Reset,
            Command::Picc,
            Command::Diagnose,
            Command::DeriveKeys,
            Command::Issuer,
        ] {
            assert_eq!(dispatch_command(command, &mut service, &mut config), WorkflowResult::Success);
        }
    }

    fn lnurl_string(value: &str) -> LnurlString {
        let mut output = LnurlString::new();
        output.push_str(value).unwrap();
        output
    }
}
