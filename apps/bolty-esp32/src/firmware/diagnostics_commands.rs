use core::fmt::Write as _;

use heapless::String;

use crate::service::{BoltyService, WorkflowResult};
use bolty_core::config::LnurlString;

use super::MAX_LINE_LEN;
use super::console_commands::{
    print_workflow_result, set_display_fail, set_display_ok, set_display_workflow_result,
};
use super::serial_console::SerialConsole;
use super::service::Esp32BoltyService;
use super::utils::{CounterDisplay, diagnose_state_label, ndef_ascii, push_uid_hex};

pub(super) fn print_help(serial: &mut SerialConsole) {
    serial.line("Commands: help status uid i2cscan hwinfo keys <k0..k4> issuer [hex] url <lnurl> burn wipe inspect picc diagnose check");
    #[cfg(feature = "board-m5stick")]
    serial.line("Buttons: button-mode [simple|legacy]");
    #[cfg(feature = "wifi")]
    serial.line("WiFi: wifi <ssid> <password> | wifi off");
    #[cfg(feature = "ota")]
    serial.line("OTA: ota <url>");
}

pub(super) fn print_i2c_scan<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
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

pub(super) fn print_hwinfo<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
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

pub(super) fn print_picc<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
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

pub(super) fn print_diagnose<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
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

pub(super) fn print_status<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
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

pub(super) fn print_uid<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
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

pub(super) fn print_inspect<I2C>(
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
