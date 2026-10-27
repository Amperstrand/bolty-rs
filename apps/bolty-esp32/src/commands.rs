use bolty_core::{
    config::{LnurlString, UrlString, WifiPasswordString, WifiSsidString},
    secret::{AesKey, CardKeys},
};

/// Button input mode for physical button behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonMode {
    Simple,
    Legacy,
}

impl ButtonMode {
    // Serial/NVS reporting on device; no host caller.
    #[cfg_attr(not(target_arch = "xtensa"), allow(dead_code))]
    pub fn as_str(self) -> &'static str {
        match self {
            ButtonMode::Simple => "simple",
            ButtonMode::Legacy => "legacy",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("simple") {
            Some(ButtonMode::Simple)
        } else if s.eq_ignore_ascii_case("legacy") {
            Some(ButtonMode::Legacy)
        } else {
            None
        }
    }
}

/// All commands the firmware accepts over serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    I2cScan,
    Uid,
    Status,
    SetKeys(CardKeys),
    SetIssuer(AesKey),
    SetUrl(LnurlString),
    SetWifi {
        ssid: WifiSsidString,
        password: WifiPasswordString,
    },
    WifiOff,
    Ota {
        url: UrlString,
        signature: heapless::String<128>,
    },
    Burn,
    Wipe,
    Ndef,
    Auth,
    Ver,
    KeyVer,
    Check,
    #[allow(dead_code)]
    DummyBurn,
    Reset,
    Inspect,
    Picc,
    Diagnose,
    DeriveKeys,
    Issuer,
    HwInfo,
    /// Query current button mode.
    ButtonMode,
    /// Set button mode.
    ButtonModeSet(ButtonMode),
    /// Set REST API bearer token. None = open access.
    SetToken(Option<bolty_core::config::RestTokenString>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    UnknownCommand,
    InvalidArgs,
    MissingArgs,
}

pub fn parse_command(line: &str) -> Result<Command, CommandError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(CommandError::UnknownCommand);
    }

    let mut parts = trimmed.split_ascii_whitespace();
    let Some(command) = parts.next() else {
        return Err(CommandError::UnknownCommand);
    };

    if command.eq_ignore_ascii_case("help") {
        expect_no_args(parts)?;
        return Ok(Command::Help);
    }
    if command.eq_ignore_ascii_case("i2cscan") {
        expect_no_args(parts)?;
        return Ok(Command::I2cScan);
    }
    if command.eq_ignore_ascii_case("uid") {
        expect_no_args(parts)?;
        return Ok(Command::Uid);
    }
    if command.eq_ignore_ascii_case("status") {
        expect_no_args(parts)?;
        return Ok(Command::Status);
    }
    if command.eq_ignore_ascii_case("keys") {
        return parse_keys_command(parts);
    }
    if command.eq_ignore_ascii_case("issuer") {
        return parse_issuer_command(parts);
    }
    if command.eq_ignore_ascii_case("url") {
        return parse_url_command(parts);
    }
    if command.eq_ignore_ascii_case("wifi") {
        return parse_wifi_command(parts);
    }
    if command.eq_ignore_ascii_case("ota") {
        return parse_ota_command(parts);
    }
    if command.eq_ignore_ascii_case("burn") {
        expect_no_args(parts)?;
        return Ok(Command::Burn);
    }
    if command.eq_ignore_ascii_case("wipe") {
        expect_no_args(parts)?;
        return Ok(Command::Wipe);
    }
    if command.eq_ignore_ascii_case("ndef") {
        expect_no_args(parts)?;
        return Ok(Command::Ndef);
    }
    if command.eq_ignore_ascii_case("auth") {
        expect_no_args(parts)?;
        return Ok(Command::Auth);
    }
    if command.eq_ignore_ascii_case("ver") {
        expect_no_args(parts)?;
        return Ok(Command::Ver);
    }
    if command.eq_ignore_ascii_case("keyver") {
        expect_no_args(parts)?;
        return Ok(Command::KeyVer);
    }
    if command.eq_ignore_ascii_case("check") {
        expect_no_args(parts)?;
        return Ok(Command::Check);
    }
    if command.eq_ignore_ascii_case("inspect") {
        expect_no_args(parts)?;
        return Ok(Command::Inspect);
    }
    if command.eq_ignore_ascii_case("picc") {
        expect_no_args(parts)?;
        return Ok(Command::Picc);
    }
    if command.eq_ignore_ascii_case("diagnose") {
        expect_no_args(parts)?;
        return Ok(Command::Diagnose);
    }
    if command.eq_ignore_ascii_case("derivekeys") {
        expect_no_args(parts)?;
        return Ok(Command::DeriveKeys);
    }
    if command.eq_ignore_ascii_case("reset") {
        expect_no_args(parts)?;
        return Ok(Command::Reset);
    }
    if command.eq_ignore_ascii_case("hwinfo") {
        expect_no_args(parts)?;
        return Ok(Command::HwInfo);
    }
    if command.eq_ignore_ascii_case("button-mode") {
        return parse_button_mode_command(parts);
    }
    if command.eq_ignore_ascii_case("token") {
        let arg = parts.next();
        if parts.next().is_some() {
            // Surplus args are rejected like every positional command —
            // `token X extra` must NOT mutate auth config (issue #148).
            return Err(CommandError::InvalidArgs);
        }
        match arg {
            None => Err(CommandError::MissingArgs),
            Some("off") | Some("none") | Some("clear") => Ok(Command::SetToken(None)),
            Some(val) => {
                let mut token = bolty_core::config::RestTokenString::new();
                token.push_str(val).map_err(|_| CommandError::InvalidArgs)?;
                Ok(Command::SetToken(Some(token)))
            }
        }
    } else {
        Err(CommandError::UnknownCommand)
    }
}

pub fn parse_hex_key(s: &str) -> Option<[u8; 16]> {
    bolty_core::util::decode_hex(s).ok()
}

/// Commands the firmware console loop handles before `handle_line`
/// (firmware.rs): they need loop-local state (buttons, NVS, feature-gated
/// provisioning) instead of the `dispatch_command` path, but their
/// matchers are pure and pinned here so the protocol table and generated
/// clients see them (issue #148 — they used to be doc-invisible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreDispatchCommand<'a> {
    Crashlog,
    HwTest,
    ProvisionCert,
    ProvisionOtaKey(&'a str),
    ForceOn,
    ForceOff,
    ForceStatus,
    GroveOn,
    GroveOff,
    GroveStatus,
}

/// First words of the pre-dispatch surface, pinned against the command
/// table in docs/serial-host-protocol.md by the tests below.
#[cfg_attr(not(test), allow(dead_code))]
pub const PRE_DISPATCH_COMMAND_WORDS: &[&str] = &[
    "crashlog",
    "hwtest",
    "provision-cert",
    "provision-ota-key",
    "force",
    "grove",
];

/// Match the pre-dispatch surface with the same framing as
/// `parse_command` (trim, ASCII-whitespace split, case-insensitive word).
/// `None` falls through to `parse_command`, which answers
/// `UnknownCommand`.
pub fn parse_pre_dispatch_command(line: &str) -> Option<PreDispatchCommand<'_>> {
    let trimmed = line.trim();
    let (head, rest) = match trimmed.find(|c: char| c.is_ascii_whitespace()) {
        Some(index) => (&trimmed[..index], Some(trimmed[index..].trim())),
        None => (trimmed, None),
    };

    if rest.is_none() {
        if head.eq_ignore_ascii_case("crashlog") {
            return Some(PreDispatchCommand::Crashlog);
        }
        if head.eq_ignore_ascii_case("hwtest") {
            return Some(PreDispatchCommand::HwTest);
        }
        if head.eq_ignore_ascii_case("provision-cert") {
            return Some(PreDispatchCommand::ProvisionCert);
        }
    }
    if head.eq_ignore_ascii_case("provision-ota-key") {
        if let Some(key_hex) = rest {
            return Some(PreDispatchCommand::ProvisionOtaKey(key_hex));
        }
    }
    if head.eq_ignore_ascii_case("force") {
        return match rest {
            None => Some(PreDispatchCommand::ForceStatus),
            Some(arg) if arg.eq_ignore_ascii_case("on") => Some(PreDispatchCommand::ForceOn),
            Some(arg) if arg.eq_ignore_ascii_case("off") => Some(PreDispatchCommand::ForceOff),
            Some(_) => None,
        };
    }
    if head.eq_ignore_ascii_case("grove") {
        // Grove 5 V boost lever (AXP192 EXTEN) — m5stick only; the handler
        // is board-gated, other boards answer unknown command.
        return match rest {
            None => Some(PreDispatchCommand::GroveStatus),
            Some(arg) if arg.eq_ignore_ascii_case("on") => Some(PreDispatchCommand::GroveOn),
            Some(arg) if arg.eq_ignore_ascii_case("off") => Some(PreDispatchCommand::GroveOff),
            Some(_) => None,
        };
    }
    None
}

fn parse_keys_command<'a>(
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<Command, CommandError> {
    let k0 = parse_key_arg(parts.next())?;
    let k1 = parse_key_arg(parts.next())?;
    let k2 = parse_key_arg(parts.next())?;
    let k3 = parse_key_arg(parts.next())?;
    let k4 = parse_key_arg(parts.next())?;

    if parts.next().is_some() {
        return Err(CommandError::InvalidArgs);
    }

    Ok(Command::SetKeys(CardKeys {
        k0: AesKey::new(k0),
        k1: AesKey::new(k1),
        k2: AesKey::new(k2),
        k3: AesKey::new(k3),
        k4: AesKey::new(k4),
    }))
}

fn parse_issuer_command<'a>(
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<Command, CommandError> {
    match parts.next() {
        None => Ok(Command::Issuer),
        Some(hex) => {
            let key = parse_hex_key(hex).ok_or(CommandError::InvalidArgs)?;
            if parts.next().is_some() {
                return Err(CommandError::InvalidArgs);
            }
            Ok(Command::SetIssuer(AesKey::new(key)))
        }
    }
}

fn parse_url_command<'a>(
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<Command, CommandError> {
    let Some(url) = parts.next() else {
        return Err(CommandError::MissingArgs);
    };
    if parts.next().is_some() {
        return Err(CommandError::InvalidArgs);
    }

    let mut lnurl = LnurlString::new();
    lnurl.push_str(url).map_err(|_| CommandError::InvalidArgs)?;
    Ok(Command::SetUrl(lnurl))
}

fn parse_wifi_command<'a>(
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<Command, CommandError> {
    let Some(first) = parts.next() else {
        return Err(CommandError::MissingArgs);
    };

    if first.eq_ignore_ascii_case("off") {
        if parts.next().is_some() {
            return Err(CommandError::InvalidArgs);
        }
        return Ok(Command::WifiOff);
    }

    let Some(password) = parts.next() else {
        return Err(CommandError::MissingArgs);
    };
    if parts.next().is_some() {
        return Err(CommandError::InvalidArgs);
    }

    let mut ssid_out = WifiSsidString::new();
    ssid_out
        .push_str(first)
        .map_err(|_| CommandError::InvalidArgs)?;

    let mut password_out = WifiPasswordString::new();
    password_out
        .push_str(password)
        .map_err(|_| CommandError::InvalidArgs)?;

    Ok(Command::SetWifi {
        ssid: ssid_out,
        password: password_out,
    })
}

fn parse_ota_command<'a>(
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<Command, CommandError> {
    let Some(url) = parts.next() else {
        return Err(CommandError::MissingArgs);
    };
    let Some(signature) = parts.next() else {
        return Err(CommandError::MissingArgs);
    };
    if parts.next().is_some() {
        return Err(CommandError::InvalidArgs);
    }

    let mut url_out = UrlString::new();
    url_out
        .push_str(url)
        .map_err(|_| CommandError::InvalidArgs)?;
    let mut sig_out = heapless::String::new();
    sig_out
        .push_str(signature)
        .map_err(|_| CommandError::InvalidArgs)?;
    Ok(Command::Ota {
        url: url_out,
        signature: sig_out,
    })
}

fn parse_key_arg(value: Option<&str>) -> Result<[u8; 16], CommandError> {
    let Some(value) = value else {
        return Err(CommandError::MissingArgs);
    };
    parse_hex_key(value).ok_or(CommandError::InvalidArgs)
}

fn parse_button_mode_command<'a>(
    mut parts: impl Iterator<Item = &'a str>,
) -> Result<Command, CommandError> {
    match parts.next() {
        None => Ok(Command::ButtonMode),
        Some(arg) => {
            let mode = ButtonMode::from_str(arg).ok_or(CommandError::InvalidArgs)?;
            if parts.next().is_some() {
                return Err(CommandError::InvalidArgs);
            }
            Ok(Command::ButtonModeSet(mode))
        }
    }
}

fn expect_no_args<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<(), CommandError> {
    if parts.next().is_some() {
        Err(CommandError::InvalidArgs)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_commands_case_insensitively() {
        assert_eq!(parse_command("  HeLp  "), Ok(Command::Help));
        assert_eq!(parse_command("I2CSCAN"), Ok(Command::I2cScan));
        assert_eq!(parse_command("STATUS"), Ok(Command::Status));
        assert_eq!(parse_command("derivekeys"), Ok(Command::DeriveKeys));
    }

    #[test]
    fn parses_keys_command() {
        let command = parse_command(
            "keys 000102030405060708090A0B0C0D0E0F 101112131415161718191A1B1C1D1E1F 202122232425262728292A2B2C2D2E2F 303132333435363738393A3B3C3D3E3F 404142434445464748494A4B4C4D4E4F",
        )
        .expect("keys command should parse");

        let Command::SetKeys(keys) = command else {
            unreachable!("expected SetKeys, got {command:?}");
        };
        assert_eq!(
            keys.k0.as_bytes(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F
            ]
        );
        assert_eq!(
            keys.k4.as_bytes(),
            &[
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
                0x4E, 0x4F
            ]
        );
    }

    #[test]
    fn parses_issuer_get_and_set() {
        assert_eq!(parse_command("issuer"), Ok(Command::Issuer));

        let command = parse_command("issuer 00112233445566778899AABBCCDDEEFF")
            .expect("issuer set should parse");

        let Command::SetIssuer(key) = command else {
            unreachable!("expected SetIssuer, got {command:?}");
        };
        assert_eq!(
            key.as_bytes(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF
            ]
        );
    }

    #[test]
    fn parses_url_command() {
        let command =
            parse_command("url https://example.com/lnurl").expect("url command should parse");
        let mut expected = LnurlString::new();
        expected.push_str("https://example.com/lnurl").unwrap();
        assert_eq!(command, Command::SetUrl(expected));
    }

    #[test]
    fn parses_wifi_commands() {
        let command =
            parse_command("wifi test-ssid supersecret").expect("wifi command should parse");
        assert_eq!(
            command,
            Command::SetWifi {
                ssid: {
                    let mut value = WifiSsidString::new();
                    value.push_str("test-ssid").unwrap();
                    value
                },
                password: {
                    let mut value = WifiPasswordString::new();
                    value.push_str("supersecret").unwrap();
                    value
                },
            }
        );

        assert_eq!(parse_command("wifi off"), Ok(Command::WifiOff));
    }

    #[test]
    fn parses_ota_command() {
        let command = parse_command("ota http://example.com/fw.bin aabbccdd")
            .expect("ota command should parse");
        assert_eq!(
            command,
            Command::Ota {
                url: {
                    let mut value = UrlString::new();
                    value.push_str("http://example.com/fw.bin").unwrap();
                    value
                },
                signature: {
                    let mut value = heapless::String::new();
                    value.push_str("aabbccdd").unwrap();
                    value
                }
            }
        );
    }

    #[test]
    fn rejects_missing_and_invalid_args() {
        assert_eq!(parse_command("keys"), Err(CommandError::MissingArgs));
        assert_eq!(parse_command("keys 00"), Err(CommandError::InvalidArgs));
        assert_eq!(parse_command("url"), Err(CommandError::MissingArgs));
        assert_eq!(parse_command("wifi"), Err(CommandError::MissingArgs));
        assert_eq!(parse_command("wifi ssid"), Err(CommandError::MissingArgs));
        assert_eq!(
            parse_command("wifi off now"),
            Err(CommandError::InvalidArgs)
        );
        assert_eq!(parse_command("ota"), Err(CommandError::MissingArgs));
        assert_eq!(
            parse_command("ota http://example.com/fw.bin"),
            Err(CommandError::MissingArgs)
        );
        assert_eq!(
            parse_command("ota http://example.com/fw.bin aabb extra"),
            Err(CommandError::InvalidArgs)
        );
        assert_eq!(parse_command("burn now"), Err(CommandError::InvalidArgs));
        assert_eq!(
            parse_command("issuer 00 extra"),
            Err(CommandError::InvalidArgs)
        );
    }

    #[test]
    fn parses_hwinfo_command() {
        assert_eq!(parse_command("hwinfo"), Ok(Command::HwInfo));
        assert_eq!(parse_command("HWINFO"), Ok(Command::HwInfo));
    }

    #[test]
    fn parses_button_mode_command() {
        assert_eq!(parse_command("button-mode"), Ok(Command::ButtonMode));
        assert_eq!(
            parse_command("button-mode simple"),
            Ok(Command::ButtonModeSet(ButtonMode::Simple))
        );
        assert_eq!(
            parse_command("BUTTON-MODE LEGACY"),
            Ok(Command::ButtonModeSet(ButtonMode::Legacy))
        );
    }

    #[test]
    fn rejects_invalid_button_mode() {
        assert_eq!(
            parse_command("button-mode invalid"),
            Err(CommandError::InvalidArgs)
        );
        assert_eq!(
            parse_command("button-mode simple extra"),
            Err(CommandError::InvalidArgs)
        );
    }

    #[test]
    fn rejects_unknown_command() {
        assert_eq!(parse_command("probe"), Err(CommandError::UnknownCommand));
        assert_eq!(parse_command("   \n"), Err(CommandError::UnknownCommand));
    }

    #[test]
    fn pins_every_no_arg_command_byte_exactly() {
        for word in [
            "help",
            "i2cscan",
            "uid",
            "status",
            "burn",
            "wipe",
            "ndef",
            "auth",
            "ver",
            "keyver",
            "check",
            "inspect",
            "picc",
            "diagnose",
            "derivekeys",
            "reset",
            "hwinfo",
        ] {
            assert!(
                parse_command(word).is_ok(),
                "{word} must parse bare (contract: docs/serial-host-protocol.md)"
            );
            assert_eq!(
                parse_command(&format!("{word} extra")),
                Err(CommandError::InvalidArgs),
                "{word} must reject surplus args"
            );
            let upper = word.to_ascii_uppercase();
            assert_eq!(
                parse_command(&upper),
                parse_command(word),
                "{word} is case-insensitive"
            );
        }
    }

    #[test]
    fn token_command_alias_and_overflow_contract() {
        for alias in ["off", "none", "clear"] {
            assert_eq!(
                parse_command(&format!("token {alias}")),
                Ok(Command::SetToken(None))
            );
        }
        assert_eq!(parse_command("token"), Err(CommandError::MissingArgs));
        let ok_token = "t".repeat(64);
        assert!(
            parse_command(&format!("token {ok_token}")).is_ok(),
            "token of exactly 64 bytes fits"
        );
        let long_token = "t".repeat(65);
        assert_eq!(
            parse_command(&format!("token {long_token}")),
            Err(CommandError::InvalidArgs),
            "token over 64 bytes is InvalidArgs (RestTokenString capacity)"
        );
    }

    #[test]
    fn token_rejects_surplus_args_without_building_settoken() {
        // Issue #148: `token X extra` used to set the token and silently
        // drop `extra` — the table promises rejection like every
        // positional command, and no SetToken may be constructed (the
        // dispatch arm mutates auth config only on a parsed command).
        assert_eq!(
            parse_command("token X extra"),
            Err(CommandError::InvalidArgs)
        );
        assert_eq!(
            parse_command("token off extra"),
            Err(CommandError::InvalidArgs)
        );
        assert_eq!(
            parse_command("token none extra extra2"),
            Err(CommandError::InvalidArgs)
        );
        let token = "t".repeat(64);
        assert_eq!(
            parse_command(&format!("token {token} extra")),
            Err(CommandError::InvalidArgs),
            "a valid-length token with surplus args still rejects"
        );
    }

    #[test]
    fn pre_dispatch_commands_parse_with_documented_framing() {
        use super::PreDispatchCommand as P;

        assert_eq!(parse_pre_dispatch_command("crashlog"), Some(P::Crashlog));
        assert_eq!(
            parse_pre_dispatch_command("  HWTEST  "),
            Some(P::HwTest),
            "trim + case-insensitive, like parse_command"
        );
        assert_eq!(
            parse_pre_dispatch_command("provision-cert"),
            Some(P::ProvisionCert)
        );
        assert_eq!(
            parse_pre_dispatch_command("PROVISION-OTA-KEY aabb"),
            Some(P::ProvisionOtaKey("aabb")),
            "case-insensitive (was case-sensitive strip_prefix, #148 true-up)"
        );
        assert_eq!(
            parse_pre_dispatch_command("provision-ota-key  aabb ccdd"),
            Some(P::ProvisionOtaKey("aabb ccdd")),
            "handler receives the raw remainder and answers with its own hex error"
        );
        assert_eq!(parse_pre_dispatch_command("force"), Some(P::ForceStatus));
        assert_eq!(parse_pre_dispatch_command("FORCE ON"), Some(P::ForceOn));
        assert_eq!(parse_pre_dispatch_command("force off"), Some(P::ForceOff));
        assert_eq!(
            parse_pre_dispatch_command("force\t on"),
            Some(P::ForceOn),
            "any ASCII whitespace separates tokens (framing rule)"
        );
    }

    #[test]
    fn pre_dispatch_malformed_lines_fall_through_to_unknown() {
        // Everything unrecognized must return None so parse_command
        // answers UnknownCommand — never a silent no-op.
        for line in [
            "",
            "   ",
            "burn",
            "crashlog extra",
            "hwtest now",
            "provision-cert x",
            "provision-ota-key",
            "force bogus",
            "force on off",
        ] {
            assert_eq!(
                parse_pre_dispatch_command(line),
                None,
                "{line:?} must fall through to parse_command"
            );
        }
    }

    #[test]
    fn protocol_table_documents_every_command_word() {
        let doc = include_str!("../../../docs/serial-host-protocol.md");
        let mut words: Vec<&str> = PRE_DISPATCH_COMMAND_WORDS.to_vec();
        words.extend([
            "help",
            "i2cscan",
            "uid",
            "status",
            "keys",
            "issuer",
            "url",
            "wifi",
            "ota",
            "burn",
            "wipe",
            "ndef",
            "auth",
            "ver",
            "keyver",
            "check",
            "inspect",
            "picc",
            "diagnose",
            "derivekeys",
            "reset",
            "hwinfo",
            "button-mode",
            "token",
        ]);
        for word in words {
            assert!(
                doc.lines()
                    .any(|row| row.starts_with(&format!("| `{word}"))),
                "docs/serial-host-protocol.md must table `{word}` (contract table = client reality)"
            );
        }
    }

    #[test]
    fn fixed_capacity_limits_are_invalid_args_not_panics() {
        let long_url = format!("https://example.com/{}", "a".repeat(256));
        assert_eq!(
            parse_command(&format!("url {long_url}")),
            Err(CommandError::InvalidArgs)
        );
        let long_ssid = "s".repeat(33);
        assert_eq!(
            parse_command(&format!("wifi {long_ssid} pass")),
            Err(CommandError::InvalidArgs),
            "ssid over 32 bytes is InvalidArgs (WifiSsidString capacity)"
        );
        let long_pass = "p".repeat(65);
        assert_eq!(
            parse_command(&format!("wifi ssid {long_pass}")),
            Err(CommandError::InvalidArgs),
            "wifi password over 64 bytes is InvalidArgs (WifiPasswordString capacity)"
        );
    }

    #[test]
    fn hex_arguments_enforce_exact_16_byte_length() {
        let short = "00".repeat(15);
        let odd = "0".repeat(33);
        let ok = "00".repeat(16);
        assert_eq!(
            parse_command(&format!("issuer {short}")),
            Err(CommandError::InvalidArgs)
        );
        assert_eq!(
            parse_command(&format!("issuer {odd}")),
            Err(CommandError::InvalidArgs)
        );
        assert!(parse_command(&format!("issuer {ok}")).is_ok());
        let four_keys = format!("{ok} {ok} {ok} {ok}");
        assert_eq!(
            parse_command(&format!("keys {four_keys}")),
            Err(CommandError::MissingArgs)
        );
    }
}
