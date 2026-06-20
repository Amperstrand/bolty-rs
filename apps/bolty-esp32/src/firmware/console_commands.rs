use core::fmt::Write as _;

use std::sync::{Arc, Mutex};

#[cfg(feature = "board-m5stick")]
use crate::button;
use crate::{
    commands::{ButtonMode, Command, CommandError, parse_command},
    service::WorkflowResult,
    workflow::dispatch_command,
};
use bolty_core::config::BoltyConfig;
use heapless::String;

#[cfg(feature = "display-st7789")]
use crate::display;
#[cfg(feature = "ota")]
use crate::ota::OtaUpdater;
#[cfg(feature = "rest")]
use crate::rest::{JobSlot, RestServer, SharedJobSlot};
#[cfg(feature = "wifi")]
use crate::wifi::WifiError;
#[cfg(feature = "ota")]
use esp_idf_hal::reset::restart;

#[cfg(feature = "rest")]
use super::REST_PORT;
use super::WifiManager;
use super::diagnostics_commands::{
    print_diagnose, print_help, print_hwinfo, print_i2c_scan, print_inspect, print_picc,
    print_status, print_uid,
};
use super::serial_console::SerialConsole;
use super::service::Esp32BoltyService;

pub(super) fn handle_line<I2C>(
    serial: &mut SerialConsole,
    line: &str,
    service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
    config: &Arc<Mutex<BoltyConfig>>,
    wifi_manager: &mut Option<WifiManager>,
    #[cfg(feature = "rest")] rest_server: &mut Option<RestServer<Esp32BoltyService<I2C>>>,
    #[cfg(feature = "rest")] job_slot: &SharedJobSlot,
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
                                Arc::clone(job_slot),
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
        Command::Ota { url, signature } => {
            match OtaUpdater::update(url.as_str(), signature.as_str()) {
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

    match &command {
        Command::ButtonMode => {
            #[cfg(feature = "board-m5stick")]
            {
                let mode = button::get_button_mode();
                serial.ok(match mode {
                    ButtonMode::Simple => "button mode: simple",
                    ButtonMode::Legacy => "button mode: legacy",
                });
            }
            #[cfg(not(feature = "board-m5stick"))]
            serial.fail("buttons not available on this board");
            return;
        }
        Command::ButtonModeSet(mode) => {
            #[cfg(feature = "board-m5stick")]
            {
                button::set_button_mode(*mode);
                super::nvs::save_button_mode(mode.as_str());
                serial.ok("button mode set");
                set_display_ok("button-mode", "mode set");
            }
            #[cfg(not(feature = "board-m5stick"))]
            {
                let _ = mode;
                serial.fail("buttons not available on this board");
            }
            return;
        }
        Command::SetToken(token) => {
            let mut config = match config.lock() {
                Ok(c) => c,
                Err(_) => {
                    serial.fail("config unavailable");
                    return;
                }
            };
            match token {
                Some(t) => {
                    config.rest_read_token = Some(t.clone());
                    config.rest_write_token = Some(t.clone());
                    serial.ok("token set");
                }
                None => {
                    config.rest_read_token = None;
                    config.rest_write_token = None;
                    serial.ok("token cleared");
                }
            }
            return;
        }
        _ => {}
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

pub(super) fn print_workflow_result(serial: &mut SerialConsole, result: WorkflowResult) {
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
        Command::ButtonMode | Command::ButtonModeSet(_) => "button-mode",
        Command::SetToken(_) => "token",
    }
}

fn command_name_from_line(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("command")
}

pub(super) fn set_display_ok(cmd_name: &str, message: &str) {
    set_display_result(cmd_name, "OK", message);
}

pub(super) fn set_display_fail(cmd_name: &str, message: &str) {
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

pub(super) fn set_display_workflow_result(cmd_name: &str, result: &WorkflowResult) {
    match result {
        WorkflowResult::Success => set_display_ok(cmd_name, "success"),
        WorkflowResult::CardNotPresent => set_display_fail(cmd_name, "card not present"),
        WorkflowResult::AuthFailed => set_display_fail(cmd_name, "authentication failed"),
        WorkflowResult::AuthDelay => set_display_fail(cmd_name, "auth delay"),
        WorkflowResult::WipeRefused => set_display_fail(cmd_name, "wipe refused"),
        WorkflowResult::Error(message) => set_display_fail(cmd_name, message.as_str()),
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
