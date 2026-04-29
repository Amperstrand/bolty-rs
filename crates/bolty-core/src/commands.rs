use crate::{
    config::{LnurlString, UrlString, WifiPasswordString, WifiSsidString},
    secret::{AesKey, CardKeys},
};

/// All commands the firmware accepts over serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
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
    Ota { url: UrlString },
    Burn,
    Wipe,
    Ndef,
    Auth,
    Ver,
    KeyVer,
    Check,
    DummyBurn,
    Reset,
    Inspect,
    Picc,
    Diagnose,
    DeriveKeys,
    Issuer,
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

    Err(CommandError::UnknownCommand)
}

pub fn parse_hex_key(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }

    let mut out = [0u8; 16];
    for (index, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Some(out)
}

fn parse_keys_command<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<Command, CommandError> {
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

fn parse_issuer_command<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<Command, CommandError> {
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

fn parse_url_command<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<Command, CommandError> {
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

fn parse_wifi_command<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<Command, CommandError> {
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

fn parse_ota_command<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<Command, CommandError> {
    let Some(url) = parts.next() else {
        return Err(CommandError::MissingArgs);
    };
    if parts.next().is_some() {
        return Err(CommandError::InvalidArgs);
    }

    let mut url_out = UrlString::new();
    url_out.push_str(url).map_err(|_| CommandError::InvalidArgs)?;
    Ok(Command::Ota { url: url_out })
}

fn parse_key_arg(value: Option<&str>) -> Result<[u8; 16], CommandError> {
    let Some(value) = value else {
        return Err(CommandError::MissingArgs);
    };
    parse_hex_key(value).ok_or(CommandError::InvalidArgs)
}

fn expect_no_args<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<(), CommandError> {
    if parts.next().is_some() {
        Err(CommandError::InvalidArgs)
    } else {
        Ok(())
    }
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_commands_case_insensitively() {
        assert_eq!(parse_command("  HeLp  "), Ok(Command::Help));
        assert_eq!(parse_command("STATUS"), Ok(Command::Status));
        assert_eq!(parse_command("derivekeys"), Ok(Command::DeriveKeys));
    }

    #[test]
    fn parses_keys_command() {
        let command = parse_command(
            "keys 000102030405060708090A0B0C0D0E0F 101112131415161718191A1B1C1D1E1F 202122232425262728292A2B2C2D2E2F 303132333435363738393A3B3C3D3E3F 404142434445464748494A4B4C4D4E4F",
        )
        .expect("keys command should parse");

        match command {
            Command::SetKeys(keys) => {
                assert_eq!(keys.k0.as_bytes(), &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
                assert_eq!(keys.k4.as_bytes(), &[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_issuer_get_and_set() {
        assert_eq!(parse_command("issuer"), Ok(Command::Issuer));

        let command = parse_command("issuer 00112233445566778899AABBCCDDEEFF")
            .expect("issuer set should parse");
        match command {
            Command::SetIssuer(key) => {
                assert_eq!(key.as_bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_url_command() {
        let command = parse_command("url https://example.com/lnurl")
            .expect("url command should parse");
        let mut expected = LnurlString::new();
        expected.push_str("https://example.com/lnurl").unwrap();
        assert_eq!(command, Command::SetUrl(expected));
    }

    #[test]
    fn parses_wifi_commands() {
        let command = parse_command("wifi test-ssid supersecret").expect("wifi command should parse");
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
        let command = parse_command("ota http://example.com/fw.bin")
            .expect("ota command should parse");
        assert_eq!(
            command,
            Command::Ota {
                url: {
                    let mut value = UrlString::new();
                    value.push_str("http://example.com/fw.bin").unwrap();
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
        assert_eq!(parse_command("wifi off now"), Err(CommandError::InvalidArgs));
        assert_eq!(parse_command("ota"), Err(CommandError::MissingArgs));
        assert_eq!(parse_command("ota http://example.com/fw.bin now"), Err(CommandError::InvalidArgs));
        assert_eq!(parse_command("burn now"), Err(CommandError::InvalidArgs));
        assert_eq!(parse_command("issuer 00 extra"), Err(CommandError::InvalidArgs));
    }

    #[test]
    fn rejects_unknown_command() {
        assert_eq!(parse_command("probe"), Err(CommandError::UnknownCommand));
        assert_eq!(parse_command("   \n"), Err(CommandError::UnknownCommand));
    }
}
