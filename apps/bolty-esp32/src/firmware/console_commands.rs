use core::fmt::Write as _;

use std::sync::{Arc, Mutex};

use crate::{
    commands::{Command, CommandError, parse_command},
    service::{BoltyService, WorkflowResult},
    workflow::dispatch_command,
};
use bolty_core::config::{BoltyConfig, LnurlString};
use heapless::String;

#[cfg(feature = "display-st7789")]
use crate::display;
#[cfg(feature = "ota")]
use crate::ota::OtaUpdater;
#[cfg(feature = "rest")]
use crate::rest::RestServer;
#[cfg(feature = "wifi")]
use crate::wifi::WifiError;
#[cfg(feature = "ota")]
use esp_idf_hal::reset::restart;

#[cfg(feature = "rest")]
use super::REST_PORT;
use super::serial_console::SerialConsole;
use super::service::Esp32BoltyService;
use super::utils::{CounterDisplay, diagnose_state_label, ndef_ascii, push_uid_hex};
use super::{MAX_LINE_LEN, WifiManager};

pub(super) fn handle_line<I2C>(
    serial: &mut SerialConsole,
    line: &str,
    service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
    config: &Arc<Mutex<BoltyConfig>>,
    wifi_manager: &mut Option<WifiManager>,
    #[cfg(feature = "rest")] rest_server: &mut Option<RestServer<Esp32BoltyService<I2C>>>,
) where
    I2C: embedded_hal::i2c::I2c + Send + 'static,
    I2C::Error: core::fmt::Debug,
{
    let command = match parse_command(line) {
        Ok(command) => command,
        Err(err) => {
            let message = command_error_message(err);
            serial.fail(message);
            set_display_fail(command_name_from_line(line), message);
            return;
        }
    };

    #[cfg(feature = "wifi")]
    match &command {
        Command::SetWifi { ssid, password } => {
            let Some(manager) = wifi_manager.as_mut() else {
                serial.fail("wifi unavailable");
                set_display_fail("wifi", "wifi unavailable");
                return;
            };
            match manager.connect(ssid, password) {
                Ok(()) => {
                    serial.ok("wifi connected");
                    set_display_ok("wifi", "wifi connected");
                    #[cfg(feature = "display-st7789")]
                    if let Some(ip) = wifi_ip_string() {
                        display::set_wifi(ip.as_str());
                    }
                    #[cfg(feature = "rest")]
                    {
                        if rest_server.is_none() {
                            match RestServer::start(
                                REST_PORT,
                                Arc::clone(config),
                                Arc::clone(service),
                            ) {
                                Ok(server) => {
                                    *rest_server = Some(server);
                                    serial.ok("rest server started");
                                    set_display_ok("wifi", "rest server started");
                                }
                                Err(err) => {
                                    let message = rest_error_message(&err);
                                    serial.fail(message.as_str());
                                    set_display_fail("wifi", message.as_str());
                                    return;
                                }
                            }
                        }

                        match manager.advertise_http_service(REST_PORT) {
                            Ok(()) => {
                                serial.ok("mdns bolty.local active");
                                set_display_ok("wifi", "mdns bolty.local active");
                            }
                            Err(err) => {
                                let message = wifi_error_message(&err);
                                serial.fail(message.as_str());
                                set_display_fail("wifi", message.as_str());
                            }
                        }
                    }
                }
                Err(err) => {
                    let message = wifi_error_message(&err);
                    serial.fail(message.as_str());
                    set_display_fail("wifi", message.as_str());
                }
            }
            return;
        }
        Command::WifiOff => {
            let Some(manager) = wifi_manager.as_mut() else {
                serial.fail("wifi unavailable");
                set_display_fail("wifi off", "wifi unavailable");
                return;
            };
            match manager.disconnect() {
                Ok(()) => {
                    #[cfg(feature = "rest")]
                    if let Some(server) = rest_server.take() {
                        server.stop();
                    }
                    #[cfg(feature = "display-st7789")]
                    display::clear_wifi();
                    serial.ok("wifi disconnected");
                    set_display_ok("wifi off", "wifi disconnected");
                }
                Err(err) => {
                    let message = wifi_error_message(&err);
                    serial.fail(message.as_str());
                    set_display_fail("wifi off", message.as_str());
                }
            }
            return;
        }
        #[cfg(feature = "ota")]
        Command::Ota { url } => {
            match OtaUpdater::update(url.as_str()) {
                Ok(()) => {
                    serial.ok("rebooting");
                    set_display_ok("ota", "rebooting");
                    restart();
                }
                Err(err) => {
                    let mut message = String::<128>::new();
                    let _ = write!(message, "{err}");
                    serial.fail(message.as_str());
                    set_display_fail("ota", message.as_str());
                }
            }
            return;
        }
        _ => {}
    }

    #[cfg(all(feature = "wifi", not(feature = "ota")))]
    if matches!(&command, Command::Ota { .. }) {
        serial.fail("ota feature disabled");
        set_display_fail("ota", "ota feature disabled");
        return;
    }

    #[cfg(not(feature = "wifi"))]
    if matches!(
        &command,
        Command::SetWifi { .. } | Command::WifiOff | Command::Ota { .. }
    ) {
        let _ = wifi_manager;
        serial.fail("wifi feature disabled");
        set_display_fail(command_name(&command), "wifi feature disabled");
        return;
    }

    let command_copy = command.clone();
    let mut config = match config.lock() {
        Ok(config) => config,
        Err(_) => {
            serial.fail("config unavailable");
            return;
        }
    };
    let mut service = match service.lock() {
        Ok(service) => service,
        Err(_) => {
            serial.fail("service unavailable");
            return;
        }
    };

    match &command {
        Command::I2cScan => {
            print_i2c_scan(serial, &mut service);
            return;
        }
        Command::Picc => {
            print_picc(serial, &mut service);
            return;
        }
        Command::Diagnose => {
            print_diagnose(serial, &mut service);
            return;
        }
        Command::HwInfo => {
            print_hwinfo(serial, &service);
            return;
        }
        _ => {}
    }

    let result = dispatch_command(command, &mut *service, &mut config);
    service.sync_from(&config);

    match command_copy {
        Command::Help => {
            print_help(serial);
            serial.ok("help");
            set_display_ok("help", "help");
        }
        Command::Status => print_status(serial, &service),
        Command::Uid => print_uid(serial, &service),
        Command::Inspect => {
            let success = matches!(&result, WorkflowResult::Success);
            print_inspect(serial, &service, result);
            #[cfg(feature = "display-st7789")]
            if success {
                display::set_event("inspect complete");
            }
        }
        _ => {
            let success = matches!(&result, WorkflowResult::Success);
            print_command_result(serial, &service, &command_copy, result);
            #[cfg(feature = "display-st7789")]
            if success {
                match &command_copy {
                    Command::Burn => display::set_event("burn complete"),
                    Command::Wipe => display::set_event("wipe complete"),
                    Command::Check => display::set_event("card is blank"),
                    _ => {}
                }
            }
        }
    }
}

pub(super) fn print_boot_banner(serial: &mut SerialConsole) {
    serial.line("=== Bolty Ready ===");
    print_help(serial);
}

fn print_help(serial: &mut SerialConsole) {
    serial.line("Commands: help status uid i2cscan hwinfo keys <k0..k4> issuer [hex] url <lnurl> burn wipe inspect picc diagnose check");
    #[cfg(feature = "wifi")]
    serial.line("WiFi: wifi <ssid> <password> | wifi off");
    #[cfg(feature = "ota")]
    serial.line("OTA: ota <url>");
}

fn print_i2c_scan<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    let found = service.i2c_scan();
    let mut line = String::<MAX_LINE_LEN>::new();
    let _ = line.push_str("i2cscan: found ");
    if found.is_empty() {
        let _ = line.push_str("none");
    } else {
        for (index, address) in found.iter().enumerate() {
            if index > 0 {
                let _ = line.push_str(", ");
            }
            let _ = write!(line, "0x{address:02X}");
        }
    }
    serial.ok(line.as_str());
    set_display_ok("i2cscan", line.as_str());
}

fn print_hwinfo<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
where
    I2C: embedded_hal::i2c::I2c,
{
    let hw = service.get_hwinfo();

    serial.line("=== Hardware Info ===");

    let mut line1 = String::<MAX_LINE_LEN>::new();
    let _ = write!(
        line1,
        "display_init={} i2c_baudrate={}Hz nfc_ready={}",
        if hw.display_init_ok { "ok" } else { "FAIL" },
        hw.i2c_baudrate,
        hw.nfc_ready,
    );
    serial.line(line1.as_str());

    let mut line2 = String::<MAX_LINE_LEN>::new();
    let _ = line2.push_str("i2c_devices: ");
    if hw.last_i2c_scan.is_empty() {
        let _ = line2.push_str("none (check cable, power, pull-ups)");
    } else {
        for (i, &addr) in hw.last_i2c_scan.iter().enumerate() {
            if i > 0 {
                let _ = line2.push_str(", ");
            }
            let _ = write!(line2, "0x{addr:02X}");
        }
    }
    serial.ok(line2.as_str());
}

fn print_picc<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    match service.picc() {
        Ok(result) => {
            let mut uid = String::<32>::new();
            let _ = push_uid_hex(&mut uid, &result.inspect.uid);
            let mut uid_line = String::<96>::new();
            let _ = write!(uid_line, "uid={}", uid.as_str());
            serial.ok(uid_line.as_str());

            match result.inspect.ndef_bytes.as_deref() {
                Some(bytes) => {
                    let ascii = ndef_ascii(bytes);
                    let mut line = String::<MAX_LINE_LEN>::new();
                    let _ = write!(line, "ndef={}", ascii.as_str());
                    serial.line(line.as_str());
                }
                None => serial.line("ndef=unavailable"),
            }

            match result.inspect.sdm_verification.as_ref() {
                Some(verification) => {
                    let mut line = String::<160>::new();
                    let read_ctr = match verification.read_ctr {
                        Some(read_ctr) => CounterDisplay::Value(read_ctr),
                        None => CounterDisplay::None,
                    };
                    let _ = write!(
                        line,
                        "sdm=ok uid_match={} read_ctr={}",
                        result.uid_match.unwrap_or(false),
                        read_ctr
                    );
                    serial.line(line.as_str());
                }
                None => serial.line("sdm=unverified"),
            }

            let mut line = String::<96>::new();
            let _ = write!(
                line,
                "keys_loaded={} keys_confirmed={}",
                result.keys_loaded, result.keys_confirmed
            );
            serial.line(line.as_str());
            serial.ok("picc complete");
            set_display_ok("picc", "picc complete");
        }
        Err(err) => {
            set_display_workflow_result("picc", &err);
            print_workflow_result(serial, err);
        }
    }
}

fn print_diagnose<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    match service.diagnose() {
        Ok(result) => {
            let mut uid = String::<32>::new();
            let _ = push_uid_hex(&mut uid, &result.inspect.uid);
            let mut line = String::<96>::new();
            let _ = write!(line, "uid={}", uid.as_str());
            serial.ok(line.as_str());

            if let Some(version) = result.inspect.version.as_ref() {
                let mut version_line = String::<96>::new();
                let _ = write!(
                    version_line,
                    "version=hw {}.{} sw {}.{}",
                    version.hw_major_version(),
                    version.hw_minor_version(),
                    version.sw_major_version(),
                    version.sw_minor_version()
                );
                serial.line(version_line.as_str());
            } else {
                serial.line("version=unavailable");
            }

            let mut fs_line = String::<128>::new();
            let _ = write!(
                fs_line,
                "file_settings={} ndef={} zero_key_attempted={} zero_key_auth_ok={}",
                result.inspect.file_settings.is_some(),
                result.inspect.ndef_bytes.is_some(),
                result.zero_key_attempted,
                result.zero_key_auth_ok
            );
            serial.line(fs_line.as_str());

            let mut state_line = String::<64>::new();
            let _ = write!(
                state_line,
                "classification={}",
                diagnose_state_label(result.state)
            );
            serial.line(state_line.as_str());
            serial.ok("diagnose complete");
            set_display_ok("diagnose", "diagnose complete");
        }
        Err(err) => {
            set_display_workflow_result("diagnose", &err);
            print_workflow_result(serial, err);
        }
    }
}

#[cfg(feature = "wifi")]
fn wifi_error_message(error: &WifiError) -> String<128> {
    let mut out = String::<128>::new();
    let _ = write!(out, "{error}");
    out
}

#[cfg(feature = "rest")]
fn rest_error_message(error: &esp_idf_sys::EspError) -> String<128> {
    let mut out = String::<128>::new();
    let _ = write!(out, "rest start failed: {error}");
    out
}

fn print_status<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
where
    I2C: embedded_hal::i2c::I2c,
{
    let status = service.get_status();
    let mut uid = String::<32>::new();
    if let Some(last_uid) = status.last_uid {
        let _ = push_uid_hex(&mut uid, &last_uid);
    }

    let mut line = String::<320>::new();
    let _ = write!(
        line,
        "nfc_ready={} uid={} lnurl={}",
        status.nfc_ready,
        if uid.is_empty() { "none" } else { uid.as_str() },
        status
            .lnurl
            .as_ref()
            .map(LnurlString::as_str)
            .unwrap_or("none")
    );
    serial.ok(line.as_str());
    set_display_ok("status", line.as_str());
}

fn print_uid<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
where
    I2C: embedded_hal::i2c::I2c,
{
    if let Some(last_uid) = service.get_status().last_uid {
        let mut uid = String::<32>::new();
        let _ = push_uid_hex(&mut uid, &last_uid);
        serial.ok(uid.as_str());
        set_display_ok("uid", uid.as_str());
    } else {
        serial.fail("no uid");
        set_display_fail("uid", "no uid");
    }
}

fn print_inspect<I2C>(
    serial: &mut SerialConsole,
    service: &Esp32BoltyService<I2C>,
    result: WorkflowResult,
) where
    I2C: embedded_hal::i2c::I2c,
{
    match result {
        WorkflowResult::Success => {
            serial.card(&service.last_card);
            serial.ok("inspect complete");
            set_display_ok("inspect", "inspect complete");
        }
        other => {
            set_display_workflow_result("inspect", &other);
            print_workflow_result(serial, other);
        }
    }
}

fn print_command_result<I2C>(
    serial: &mut SerialConsole,
    service: &Esp32BoltyService<I2C>,
    command: &Command,
    result: WorkflowResult,
) where
    I2C: embedded_hal::i2c::I2c,
{
    match (command, result) {
        (Command::Check, WorkflowResult::Success) => {
            serial.card(&service.last_card);
            serial.ok("card is blank");
            set_display_ok(command_name(command), "card is blank");
        }
        (Command::SetKeys(_), WorkflowResult::Success) => {
            serial.ok("keys staged");
            serial.line("[ADVANCED] Raw keys override the standard Bolt Card");
            serial.line("deterministic key derivation (boltcard.org spec).");
            serial.line("Prefer: 'issuer <hex>' + 'burn' for correct key derivation.");
            serial.line("       from CardKey = CMAC(IssuerKey, 2D003F75 || UID || ver)");
            set_display_ok(command_name(command), "keys staged");
        }
        (Command::SetIssuer(_), WorkflowResult::Success) => {
            serial.ok("issuer staged");
            set_display_ok(command_name(command), "issuer staged");
        }
        (Command::SetUrl(_), WorkflowResult::Success) => {
            serial.ok("lnurl staged");
            set_display_ok(command_name(command), "lnurl staged");
        }
        (Command::Burn, WorkflowResult::Success) => {
            serial.ok("burn complete");
            set_display_ok(command_name(command), "burn complete");
        }
        (Command::Wipe, WorkflowResult::Success) => {
            serial.ok("wipe complete");
            set_display_ok(command_name(command), "wipe complete");
        }
        (_, other) => {
            set_display_workflow_result(command_name(command), &other);
            print_workflow_result(serial, other);
        }
    }
}

fn print_workflow_result(serial: &mut SerialConsole, result: WorkflowResult) {
    match result {
        WorkflowResult::Success => serial.ok("success"),
        WorkflowResult::CardNotPresent => serial.fail("card not present"),
        WorkflowResult::AuthFailed => serial.fail("authentication failed"),
        WorkflowResult::AuthDelay => {
            serial.fail("AUTH DELAY (0x91AD): Card authentication failure counter triggered.");
            serial.line("Remove card from reader field for several seconds and retry.");
            serial.line("Ensure you are using the correct key.");
        }
        WorkflowResult::WipeRefused => serial.fail("wipe refused"),
        WorkflowResult::Error(message) => serial.fail(message.as_str()),
    }
}

#[cfg(all(feature = "display-st7789", feature = "wifi"))]
fn wifi_ip_string() -> Option<String<16>> {
    let key = b"WIFI_STA_DEF\0";
    let handle = unsafe { esp_idf_sys::esp_netif_get_handle_from_ifkey(key.as_ptr().cast()) };
    if handle.is_null() {
        return None;
    }

    let mut ip_info: esp_idf_sys::esp_netif_ip_info_t = Default::default();
    let rc = unsafe { esp_idf_sys::esp_netif_get_ip_info(handle, &mut ip_info) };
    if rc != 0 {
        return None;
    }

    let mut out = String::<16>::new();
    let [a, b, c, d] = ip_info.ip.addr.to_le_bytes();
    write!(out, "{a}.{b}.{c}.{d}").ok()?;
    Some(out)
}

fn command_error_message(error: CommandError) -> &'static str {
    match error {
        CommandError::UnknownCommand => "unknown command",
        CommandError::InvalidArgs => "invalid arguments",
        CommandError::MissingArgs => "missing arguments",
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Help => "help",
        Command::Status => "status",
        Command::Uid => "uid",
        Command::I2cScan => "i2cscan",
        Command::SetKeys(_) => "keys",
        Command::SetIssuer(_) | Command::Issuer => "issuer",
        Command::SetUrl(_) => "url",
        Command::Burn => "burn",
        Command::Wipe => "wipe",
        Command::Ndef => "ndef",
        Command::Auth => "auth",
        Command::Ver => "ver",
        Command::KeyVer => "keyver",
        Command::Inspect => "inspect",
        Command::Picc => "picc",
        Command::Diagnose => "diagnose",
        Command::HwInfo => "hwinfo",
        Command::Check => "check",
        Command::DummyBurn => "dummyburn",
        Command::Reset => "reset",
        Command::DeriveKeys => "derivekeys",
        Command::SetWifi { .. } => "wifi",
        Command::WifiOff => "wifi off",
        Command::Ota { .. } => "ota",
    }
}

fn command_name_from_line(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("command")
}

fn set_display_ok(cmd_name: &str, message: &str) {
    set_display_result(cmd_name, "OK", message);
}

fn set_display_fail(cmd_name: &str, message: &str) {
    set_display_result(cmd_name, "FAIL", message);
}

fn set_display_result(cmd_name: &str, status: &str, message: &str) {
    #[cfg(feature = "display-st7789")]
    {
        let mut result = String::<64>::new();
        let _ = write!(result, "{status}: {message}");
        display::set_command_result(cmd_name, result.as_str());
    }

    #[cfg(not(feature = "display-st7789"))]
    let _ = (cmd_name, status, message);
}

fn set_display_workflow_result(cmd_name: &str, result: &WorkflowResult) {
    match result {
        WorkflowResult::Success => set_display_ok(cmd_name, "success"),
        WorkflowResult::CardNotPresent => set_display_fail(cmd_name, "card not present"),
        WorkflowResult::AuthFailed => set_display_fail(cmd_name, "authentication failed"),
        WorkflowResult::AuthDelay => set_display_fail(cmd_name, "auth delay"),
        WorkflowResult::WipeRefused => set_display_fail(cmd_name, "wipe refused"),
        WorkflowResult::Error(message) => set_display_fail(cmd_name, message.as_str()),
    }
}
