use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bolty_core::config::BoltyConfig;
use bolty_mfrc522::{DEFAULT_I2C_ADDRESS, Mfrc522Transceiver};

use esp_idf_hal::{
    delay::FreeRtos,
    i2c::{I2cConfig, I2cDriver},
    peripherals::Peripherals,
    units::FromValueType,
};
use esp_idf_sys as _;
use heapless::String;
use log::info;

use core::fmt::Write as _;

#[cfg(feature = "board-m5stick")]
use crate::button::{self, ButtonEvent, ButtonHandler};
#[cfg(feature = "board-m5stick")]
use crate::commands::ButtonMode;
#[cfg(feature = "display-st7789")]
use crate::display;
#[cfg(feature = "board-m5stick")]
use crate::service::BoltyService;
#[cfg(feature = "wifi")]
use crate::wifi::WifiManager;

mod utils;
use utils::{card_state_label, millis, push_uid_hex, scan_i2c_bus};

mod serial_console;
use serial_console::SerialConsole;

mod service;
use service::Esp32BoltyService;

mod console_commands;
use console_commands::{handle_line, print_boot_banner};

mod card_operations;
mod diagnostics_commands;

mod nvs;

#[cfg(not(feature = "wifi"))]
struct WifiManager;

#[cfg(feature = "board-m5atom")]
const BOARD_NAME: &str = "M5Atom";
#[cfg(feature = "board-m5stick")]
const BOARD_NAME: &str = "M5StickC Plus";

pub(super) fn gen_rnd_a() -> [u8; 16] {
    let mut buf = [0u8; 16];
    unsafe { esp_idf_sys::esp_fill_random(buf.as_mut_ptr().cast(), buf.len()) };
    buf
}

const I2C_BAUDRATE_HZ: u32 = 100_000;
pub(super) const MAX_LINE_LEN: usize = 512;
pub(super) const SERIAL_FD_IN: i32 = 0;
pub(super) const SERIAL_FD_OUT: i32 = 1;
const CARD_POLL_INTERVAL_MS: u64 = 500;
const MAIN_LOOP_DELAY_MS: u32 = 10;
const BATTERY_UPDATE_INTERVAL_MS: u64 = 5_000;
static DISPLAY_INIT_OK: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rest")]
pub(super) const REST_PORT: u16 = 80;

#[cfg(feature = "board-m5stick")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyOp {
    Idle,
    Burn,
    Wipe,
}

pub fn main() {
    esp_idf_sys::link_patches();
    esp_idf_hal::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = match Peripherals::take() {
        Ok(peripherals) => peripherals,
        Err(_) => fatal_halt("peripherals already taken"),
    };

    #[cfg(feature = "led-matrix")]
    neopixel_off(peripherals.pins.gpio27);

    #[cfg(feature = "wifi")]
    let modem = peripherals.modem;

    #[cfg(feature = "ble")]
    let modem = peripherals.modem;

    #[cfg(feature = "display-st7789")]
    {
        let result = unsafe {
            display::init(
                peripherals.i2c1,
                peripherals.spi2,
                peripherals.pins.gpio21,
                peripherals.pins.gpio22,
                peripherals.pins.gpio13,
                peripherals.pins.gpio15,
                peripherals.pins.gpio5,
                peripherals.pins.gpio23,
                peripherals.pins.gpio18,
                peripherals.pins.gpio27,
                BOARD_NAME,
            )
        };
        DISPLAY_INIT_OK.store(result.is_ok(), Ordering::SeqCst);
        if let Err(e) = result {
            log::error!("Display init failed: {e}");
        }
    }

    #[cfg(feature = "board-m5atom")]
    let (i2c_sda, i2c_scl) = (peripherals.pins.gpio26, peripherals.pins.gpio32);
    #[cfg(feature = "board-m5stick")]
    let (i2c_sda, i2c_scl) = (peripherals.pins.gpio32, peripherals.pins.gpio33);

    #[cfg(feature = "board-m5atom")]
    let (i2c_sda_pin, i2c_scl_pin) = (26i32, 32i32);
    #[cfg(feature = "board-m5stick")]
    let (i2c_sda_pin, i2c_scl_pin) = (32i32, 33i32);

    recover_i2c_bus(i2c_scl_pin, i2c_sda_pin);

    FreeRtos::delay_ms(50);

    let mut i2c = match I2cDriver::new(
        peripherals.i2c0,
        i2c_sda,
        i2c_scl,
        &I2cConfig::new().baudrate(I2C_BAUDRATE_HZ.Hz()),
    ) {
        Ok(i2c) => i2c,
        Err(e) => fatal_halt(&format!("I2C0 init failed: {e:?}")),
    };
    log::info!("I2C0 initialized ({BOARD_NAME}) @ {}Hz", I2C_BAUDRATE_HZ);

    let initial_i2c_scan = scan_i2c_bus(&mut i2c);
    let mfrc522_seen = initial_i2c_scan
        .iter()
        .any(|&address| address == DEFAULT_I2C_ADDRESS);

    let (xcvr, raw_i2c, nfc_ready) = if mfrc522_seen {
        match Mfrc522Transceiver::from_i2c(i2c, DEFAULT_I2C_ADDRESS) {
            Ok(xcvr) => {
                log::info!("MFRC522 initialized at 0x{:02X}", DEFAULT_I2C_ADDRESS);
                (Some(xcvr), None, true)
            }
            Err(e) => {
                log::warn!("MFRC522 init failed, continuing without NFC: {e:?}");
                (None, None, false)
            }
        }
    } else {
        log::warn!(
            "MFRC522 not detected at 0x{:02X}; continuing without NFC",
            DEFAULT_I2C_ADDRESS
        );
        (None, Some(i2c), false)
    };

    let mut serial = SerialConsole::new();
    let mut initial_config = BoltyConfig::default();
    initial_config.lnurl = nvs::load_lnurl();
    let config = Arc::new(Mutex::new(initial_config.clone()));
    let display_ok = DISPLAY_INIT_OK.load(Ordering::SeqCst);
    let service = Arc::new(Mutex::new(Esp32BoltyService::new(
        xcvr,
        raw_i2c,
        initial_i2c_scan.clone(),
        initial_config,
        display_ok,
        I2C_BAUDRATE_HZ,
    )));

    #[cfg(feature = "display-st7789")]
    display::set_nfc_ready(nfc_ready);
    #[cfg(feature = "wifi")]
    let mut wifi_manager = match WifiManager::new(modem) {
        Ok(manager) => Some(manager),
        Err(err) => {
            info!("wifi init unavailable: {err}");
            None
        }
    };
    #[cfg(not(feature = "wifi"))]
    let mut wifi_manager: Option<WifiManager> = None;
    #[cfg(feature = "rest")]
    let mut rest_server = None;
    let mut line = String::<MAX_LINE_LEN>::new();
    let mut next_poll_at = millis();
    let mut heartbeat_at = millis();
    let mut card_announced = false;

    let boot_count = nvs::load_boot_count().saturating_add(1);
    nvs::save_boot_count(boot_count);

    let reset_reason = unsafe { esp_idf_sys::esp_reset_reason() };
    let reset_label = match reset_reason {
        1 => "POWERON",
        3 => "SW_RESET",
        4 => "PANIC",
        5 => "INT_WDT",
        6 => "TASK_WDT",
        7 => "WDT",
        8 => "DEEPSLEEP",
        9 => "BROWNOUT",
        _ => "UNKNOWN",
    };

    let abnormal = matches!(reset_reason, 4 | 5 | 6 | 7 | 9);
    if abnormal {
        nvs::save_crash_info(reset_reason as u8, boot_count.saturating_sub(1));
        log::warn!("ABNORMAL RESET: {} (boot {})", reset_label, boot_count - 1);
    }

    serial.line(&format!("[BOOT] #{boot_count} reason={reset_label}"));

    // Hardware diagnostics on serial console (visible even if boot logs were missed)
    {
        let mut diag = String::<256>::new();
        let _ = write!(
            diag,
            "hw: board={} i2c={}Hz display={} nfc={}",
            BOARD_NAME,
            I2C_BAUDRATE_HZ,
            if display_ok { "ok" } else { "FAIL" },
            if nfc_ready { "ok" } else { "missing" },
        );
        serial.line(diag.as_str());

        let mut scan_line = String::<128>::new();
        let _ = scan_line.push_str("hw: i2c_scan=");
        if initial_i2c_scan.is_empty() {
            let _ = scan_line.push_str("none");
        } else {
            for (i, &addr) in initial_i2c_scan.iter().enumerate() {
                if i > 0 {
                    let _ = scan_line.push_str(",");
                }
                let _ = write!(scan_line, "0x{addr:02X}");
            }
        }
        serial.line(scan_line.as_str());
    }

    info!("=== Bolty Ready ===");
    print_boot_banner(&mut serial);

    #[cfg(feature = "display-st7789")]
    display::set_event("ready");

    #[cfg(feature = "ble")]
    let ble_transport = {
        log::info!("Initializing BLE transport...");
        match crate::ble::BleTransport::start(modem) {
            Ok(t) => {
                log::info!("BLE transport initialized");
                if !crate::ble::wait_for_ready(&t, 5000) {
                    log::warn!("BLE: GATT server not ready after 5s, continuing anyway");
                }
                Some(t)
            }
            Err(e) => {
                log::error!("BLE init failed: {e:?}");
                None
            }
        }
    };

    #[cfg(feature = "board-m5stick")]
    let mut buttons: Option<ButtonHandler> = {
        let front = esp_idf_hal::gpio::PinDriver::input(
            peripherals.pins.gpio37,
            esp_idf_hal::gpio::Pull::Up,
        );
        let side = esp_idf_hal::gpio::PinDriver::input(
            peripherals.pins.gpio39,
            esp_idf_hal::gpio::Pull::Up,
        );
        match (front, side) {
            (Ok(f), Ok(s)) => {
                log::info!("Buttons: GPIO37 front + GPIO39 side");
                Some(ButtonHandler::new(f, s))
            }
            (front_err, side_err) => {
                if let Err(ref e) = front_err {
                    log::warn!("GPIO37 front button failed: {e:?}");
                }
                if let Err(ref e) = side_err {
                    log::warn!("GPIO39 side button failed: {e:?}");
                }
                None
            }
        }
    };

    #[cfg(feature = "board-m5stick")]
    {
        let saved_mode = nvs::load_button_mode();
        let mode = saved_mode
            .as_deref()
            .and_then(ButtonMode::from_str)
            .unwrap_or(ButtonMode::Simple);
        button::set_button_mode(mode);
        log::info!("Button mode: {:?}", mode);
    }

    #[cfg(feature = "board-m5stick")]
    let mut legacy_op = LegacyOp::Idle;

    #[cfg(feature = "display-st7789")]
    let mut next_battery_update = millis();

    loop {
        while let Some(byte) = serial.read_byte_nonblocking() {
            match byte {
                b'\r' => {}
                b'\n' => {
                    if !line.is_empty() {
                        if line.trim().eq_ignore_ascii_case("crashlog") {
                            run_crashlog(&mut serial);
                        } else if line.trim().eq_ignore_ascii_case("hwtest") {
                            run_hwtest(&mut serial, &mut buttons, &service);
                        } else {
                            handle_line(
                                &mut serial,
                                line.as_str(),
                                &service,
                                &config,
                                &mut wifi_manager,
                                #[cfg(feature = "rest")]
                                &mut rest_server,
                            );
                        }
                        line.clear();
                        card_announced = false;
                    }
                }
                _ => {
                    if line.push(byte as char).is_err() {
                        serial.fail("command too long");
                        line.clear();
                    }
                }
            }
        }

        #[cfg(feature = "ble")]
        if let Some(ref bt) = ble_transport {
            while let Some(cmd) = bt.poll_command() {
                log::info!("BLE cmd: {cmd}");
                let response = process_ble_command(&cmd, &service, &config);
                bt.send_response(&response);
            }
        }

        let now = millis();
        if now >= next_poll_at {
            poll_card(&mut serial, &service, &mut card_announced);
            next_poll_at = now.saturating_add(CARD_POLL_INTERVAL_MS);
        }

        if now >= heartbeat_at {
            let mut hb = String::<48>::new();
            let _ = write!(hb, "[HB] alive t={}ms", now);
            serial.line(hb.as_str());
            heartbeat_at = now.saturating_add(10_000);
        }

        #[cfg(feature = "display-st7789")]
        if now >= next_battery_update {
            display::update_battery();
            next_battery_update = now.saturating_add(BATTERY_UPDATE_INTERVAL_MS);
        }

        #[cfg(feature = "board-m5stick")]
        if let Some(ref mut handler) = buttons {
            let (front_event, side_event) = handler.poll(now);
            if front_event != ButtonEvent::None || side_event != ButtonEvent::None {
                handle_button_events(
                    front_event,
                    side_event,
                    &mut serial,
                    &service,
                    &config,
                    &mut wifi_manager,
                    &mut legacy_op,
                );
            }
        }

        FreeRtos::delay_ms(MAIN_LOOP_DELAY_MS);
    }
}

fn poll_card<I2C>(
    serial: &mut SerialConsole,
    service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
    card_announced: &mut bool,
) where
    I2C: embedded_hal::i2c::I2c,
    I2C::Error: core::fmt::Debug,
{
    let mut service = match service.lock() {
        Ok(service) => service,
        Err(_) => return,
    };

    if !service.nfc_available() {
        *card_announced = false;
        #[cfg(feature = "display-st7789")]
        display::clear_card();
        return;
    }

    // Once a card has been announced, use a lightweight ISO 14443A presence
    // check instead of re-authenticating. Re-authenticating every poll cycle
    // increments the NTAG424's SeqFailCtr and bricks cards after 50 failures.
    if *card_announced {
        if !service.card_present() {
            *card_announced = false;
            #[cfg(feature = "display-st7789")]
            display::clear_card();
        }
        return;
    }

    match service.poll_safe() {
        None => {
            *card_announced = false;
            #[cfg(feature = "display-st7789")]
            display::clear_card();
        }
        Some(assessment) => {
            if !*card_announced && assessment.present {
                serial.card(&assessment);
                *card_announced = true;
                #[cfg(feature = "display-st7789")]
                {
                    let mut uid_hex = heapless::String::<16>::new();
                    if let Some(uid) = assessment.uid.as_ref() {
                        let _ = push_uid_hex(&mut uid_hex, &uid[..assessment.uid_len as usize]);
                    }
                    display::set_card(uid_hex.as_str(), card_state_label(assessment.state));
                }
            }
        }
    }
}

#[cfg(feature = "board-m5stick")]
fn handle_button_events<I2C>(
    front: ButtonEvent,
    side: ButtonEvent,
    serial: &mut SerialConsole,
    service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
    config: &Arc<Mutex<BoltyConfig>>,
    wifi_manager: &mut Option<WifiManager>,
    legacy_op: &mut LegacyOp,
) where
    I2C: embedded_hal::i2c::I2c + Send + 'static,
    I2C::Error: core::fmt::Debug,
{
    use bolty_core::assessment::CardState;

    let mode = button::get_button_mode();

    match mode {
        ButtonMode::Simple => {
            if front == ButtonEvent::Click {
                do_smart_action(serial, service, config);
            } else if front == ButtonEvent::LongPress {
                toggle_wifi_button(wifi_manager, serial);
            }
            if side == ButtonEvent::Click {
                show_button_status(serial, service);
            } else if side == ButtonEvent::LongPress {
                enter_deep_sleep();
            }
        }
        ButtonMode::Legacy => {
            if front == ButtonEvent::Click {
                *legacy_op = match *legacy_op {
                    LegacyOp::Idle => LegacyOp::Burn,
                    LegacyOp::Burn => LegacyOp::Wipe,
                    LegacyOp::Wipe => LegacyOp::Idle,
                };
                #[cfg(feature = "display-st7789")]
                display::set_mode(match *legacy_op {
                    LegacyOp::Idle => display::DisplayMode::Idle,
                    LegacyOp::Burn => display::DisplayMode::Burn,
                    LegacyOp::Wipe => display::DisplayMode::Wipe,
                });
                let label = match *legacy_op {
                    LegacyOp::Idle => "mode: idle",
                    LegacyOp::Burn => "mode: burn",
                    LegacyOp::Wipe => "mode: wipe",
                };
                serial.line(label);
            } else if front == ButtonEvent::LongPress {
                toggle_wifi_button(wifi_manager, serial);
            }
            if side == ButtonEvent::Click {
                match *legacy_op {
                    LegacyOp::Burn => do_burn_button(serial, service, config),
                    LegacyOp::Wipe => do_wipe_button(serial, service, config),
                    LegacyOp::Idle => serial.fail("no action (idle mode)"),
                }
            } else if side == ButtonEvent::LongPress {
                enter_deep_sleep();
            }
        }
    }

    fn do_smart_action<I2C2>(
        serial: &mut SerialConsole,
        service: &Arc<Mutex<Esp32BoltyService<I2C2>>>,
        config: &Arc<Mutex<BoltyConfig>>,
    ) where
        I2C2: embedded_hal::i2c::I2c + Send + 'static,
        I2C2::Error: core::fmt::Debug,
    {
        let svc = match service.lock() {
            Ok(s) => s,
            Err(_) => {
                serial.fail("service unavailable");
                return;
            }
        };
        match svc.last_card.state {
            CardState::Blank => {
                drop(svc);
                do_burn_button(serial, service, config);
            }
            CardState::Provisioned(_) => {
                drop(svc);
                do_wipe_button(serial, service, config);
            }
            _ => {
                serial.fail("no card or unknown state");
            }
        }
    }

    fn do_burn_button<I2C2>(
        serial: &mut SerialConsole,
        service: &Arc<Mutex<Esp32BoltyService<I2C2>>>,
        config: &Arc<Mutex<BoltyConfig>>,
    ) where
        I2C2: embedded_hal::i2c::I2c + Send + 'static,
        I2C2::Error: core::fmt::Debug,
    {
        let config = match config.lock() {
            Ok(c) => c,
            Err(_) => {
                serial.fail("config unavailable");
                return;
            }
        };
        let mut svc = match service.lock() {
            Ok(s) => s,
            Err(_) => {
                serial.fail("service unavailable");
                return;
            }
        };

        if config.pending_issuer.is_none() && config.pending_keys.is_none() {
            serial.fail("no issuer or keys");
            return;
        }
        let lnurl = config.lnurl.as_ref().map(|s| s.as_str()).unwrap_or("");
        if lnurl.is_empty() {
            serial.fail("no lnurl configured");
            return;
        }

        let result = svc.burn(
            config.pending_issuer.as_ref(),
            config.pending_keys.as_ref(),
            lnurl,
        );
        svc.sync_from(&config);
        report_button_result(serial, "burn", result);
    }

    fn do_wipe_button<I2C2>(
        serial: &mut SerialConsole,
        service: &Arc<Mutex<Esp32BoltyService<I2C2>>>,
        config: &Arc<Mutex<BoltyConfig>>,
    ) where
        I2C2: embedded_hal::i2c::I2c + Send + 'static,
        I2C2::Error: core::fmt::Debug,
    {
        let config = match config.lock() {
            Ok(c) => c,
            Err(_) => {
                serial.fail("config unavailable");
                return;
            }
        };
        let mut svc = match service.lock() {
            Ok(s) => s,
            Err(_) => {
                serial.fail("service unavailable");
                return;
            }
        };

        if config.pending_issuer.is_none() && config.pending_keys.is_none() {
            serial.fail("no issuer or keys");
            return;
        }

        let result = svc.wipe(config.pending_issuer.as_ref(), config.pending_keys.as_ref());
        report_button_result(serial, "wipe", result);
    }

    fn report_button_result(
        serial: &mut SerialConsole,
        action: &str,
        result: crate::service::WorkflowResult,
    ) {
        use crate::service::WorkflowResult;
        match result {
            WorkflowResult::Success => {
                let mut msg = heapless::String::<32>::new();
                let _ = write!(msg, "[OK] {action} complete (button)");
                serial.line(msg.as_str());
                #[cfg(feature = "display-st7789")]
                {
                    display::set_event(&format!("{action} ok"));
                    display::set_mode(display::DisplayMode::Idle);
                }
            }
            ref err => {
                #[cfg(feature = "display-st7789")]
                display::set_mode(display::DisplayMode::Error);

                let mut msg = heapless::String::<64>::new();
                let _ = match err {
                    WorkflowResult::CardNotPresent => write!(msg, "[FAIL] {action}: no card"),
                    WorkflowResult::AuthFailed => write!(msg, "[FAIL] {action}: auth failed"),
                    WorkflowResult::AuthDelay => write!(msg, "[FAIL] {action}: auth delay"),
                    WorkflowResult::WipeRefused => write!(msg, "[FAIL] {action}: refused"),
                    WorkflowResult::Error(e) => write!(msg, "[FAIL] {action}: {}", e.as_str()),
                    WorkflowResult::Success => unreachable!(),
                };
                serial.line(msg.as_str());
            }
        }
    }

    fn show_button_status<I2C2>(
        serial: &mut SerialConsole,
        service: &Arc<Mutex<Esp32BoltyService<I2C2>>>,
    ) where
        I2C2: embedded_hal::i2c::I2c,
        I2C2::Error: core::fmt::Debug,
    {
        let svc = match service.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        let status = svc.get_status();
        serial.card(&svc.last_card);
        let mut line = heapless::String::<96>::new();
        let _ = write!(
            line,
            "[INFO] nfc={} lnurl={}",
            if status.nfc_ready { "ok" } else { "--" },
            status.lnurl.as_ref().map(|l| l.as_str()).unwrap_or("none"),
        );
        serial.line(line.as_str());
    }

    fn toggle_wifi_button(wifi_manager: &mut Option<WifiManager>, serial: &mut SerialConsole) {
        #[cfg(feature = "wifi")]
        {
            if let Some(manager) = wifi_manager {
                if manager.is_connected() {
                    match manager.disconnect() {
                        Ok(()) => {
                            #[cfg(feature = "display-st7789")]
                            display::clear_wifi();
                            serial.line("[OK] wifi off (button)");
                        }
                        Err(_) => serial.fail("wifi disconnect failed"),
                    }
                } else {
                    serial.fail("wifi not configured (use serial)");
                }
            } else {
                serial.fail("wifi unavailable");
            }
        }
        #[cfg(not(feature = "wifi"))]
        {
            let _ = wifi_manager;
            serial.fail("wifi not enabled");
        }
    }

    fn enter_deep_sleep() -> ! {
        log::info!("Deep sleep (wake: side button GPIO39)");
        #[cfg(feature = "display-st7789")]
        display::set_event("sleep");
        unsafe {
            esp_idf_sys::esp_sleep_enable_ext0_wakeup(esp_idf_sys::gpio_num_t_GPIO_NUM_39, 0);
            esp_idf_sys::esp_deep_sleep_start();
        }
    }
}

fn recover_i2c_bus(scl_pin: i32, sda_pin: i32) {
    use esp_idf_sys::{
        esp_rom_delay_us, gpio_config, gpio_config_t, gpio_get_level, gpio_reset_pin,
        gpio_set_level,
    };

    const GPIO_MODE_INPUT: u32 = 1;
    const GPIO_MODE_OUTPUT: u32 = 2;

    let mask = |pin: i32| -> u64 { 1u64 << pin };

    let sda_cfg = gpio_config_t {
        pin_bit_mask: mask(sda_pin),
        mode: GPIO_MODE_INPUT as u32,
        pull_up_en: 1,
        pull_down_en: 0,
        intr_type: 0,
    };

    let result = unsafe { gpio_config(&sda_cfg) };
    if result != 0 {
        log::warn!("I2C recovery: SDA gpio_config failed: {result}");
        return;
    }

    if unsafe { gpio_get_level(sda_pin) } != 0 {
        log::info!("I2C recovery: SDA high, bus OK — no recovery needed");
        unsafe {
            gpio_reset_pin(sda_pin);
        }
        return;
    }

    log::warn!("I2C recovery: SDA stuck LOW — sending 9 SCL clock pulses");

    let scl_cfg = gpio_config_t {
        pin_bit_mask: mask(scl_pin),
        mode: GPIO_MODE_OUTPUT as u32,
        pull_up_en: 1,
        pull_down_en: 0,
        intr_type: 0,
    };

    let result = unsafe { gpio_config(&scl_cfg) };
    if result != 0 {
        log::warn!("I2C recovery: SCL gpio_config failed: {result}");
        unsafe {
            gpio_reset_pin(sda_pin);
        }
        return;
    }

    for _ in 0..9 {
        unsafe {
            gpio_set_level(scl_pin, 1);
            esp_rom_delay_us(10);
            gpio_set_level(scl_pin, 0);
            esp_rom_delay_us(10);
        }
    }

    let recovered = unsafe { gpio_get_level(sda_pin) } != 0;
    log::info!(
        "I2C recovery: {}",
        if recovered {
            "SDA released — OK"
        } else {
            "SDA still LOW — may need power cycle"
        }
    );

    unsafe {
        gpio_reset_pin(scl_pin);
        gpio_reset_pin(sda_pin);
    }
}

/// Delayed halt with periodic re-logging and eventual software restart.
fn fatal_halt(context: &str) -> ! {
    const RELOG_INTERVAL_MS: u32 = 5000;
    const MAX_ATTEMPTS: u32 = 6;

    for attempt in 1..=MAX_ATTEMPTS {
        log::error!("FATAL: {context} (attempt {attempt}/{MAX_ATTEMPTS})");
        FreeRtos::delay_ms(RELOG_INTERVAL_MS);
    }

    log::error!("FATAL: {context} — restarting device");
    FreeRtos::delay_ms(100);
    unsafe { esp_idf_sys::esp_restart() };
    #[allow(unreachable_code)]
    loop {
        FreeRtos::delay_ms(RELOG_INTERVAL_MS);
    }
}

#[cfg(feature = "led-matrix")]
fn neopixel_off(pin: esp_idf_hal::gpio::Gpio27) {
    use core::time::Duration;
    use esp_idf_hal::rmt::config::{TransmitConfig, TxChannelConfig};
    use esp_idf_hal::rmt::encoder::{BytesEncoder, BytesEncoderConfig};
    use esp_idf_hal::rmt::{PinState, Pulse, Symbol, TxChannelDriver};
    use esp_idf_hal::units::FromValueType as _;

    let config = TxChannelConfig {
        resolution: 10.MHz().into(),
        ..Default::default()
    };

    let mut tx = match TxChannelDriver::new(pin, &config) {
        Ok(tx) => tx,
        Err(e) => {
            log::warn!("NeoPixel RMT init failed: {e:?}");
            return;
        }
    };

    let Ok(t0h) =
        Pulse::new_with_duration(10.MHz().into(), PinState::High, Duration::from_nanos(350))
    else {
        log::warn!("NeoPixel pulse config failed: t0h");
        return;
    };
    let Ok(t0l) =
        Pulse::new_with_duration(10.MHz().into(), PinState::Low, Duration::from_nanos(800))
    else {
        log::warn!("NeoPixel pulse config failed: t0l");
        return;
    };
    let Ok(t1h) =
        Pulse::new_with_duration(10.MHz().into(), PinState::High, Duration::from_nanos(700))
    else {
        log::warn!("NeoPixel pulse config failed: t1h");
        return;
    };
    let Ok(t1l) =
        Pulse::new_with_duration(10.MHz().into(), PinState::Low, Duration::from_nanos(600))
    else {
        log::warn!("NeoPixel pulse config failed: t1l");
        return;
    };

    let encoder_config = BytesEncoderConfig {
        bit0: Symbol::new(t0h, t0l),
        bit1: Symbol::new(t1h, t1l),
        msb_first: true,
        ..Default::default()
    };

    let encoder = match BytesEncoder::with_config(&encoder_config) {
        Ok(encoder) => encoder,
        Err(e) => {
            log::warn!("NeoPixel encoder init failed: {e:?}");
            return;
        }
    };

    let black: [u8; 75] = [0u8; 75];
    if let Err(e) = tx.send_and_wait(encoder, &black, &TransmitConfig::default()) {
        log::warn!("NeoPixel write failed: {e:?}");
    }
}

fn run_crashlog(serial: &mut SerialConsole) {
    let boot_count = nvs::load_boot_count();
    let reset_reason = unsafe { esp_idf_sys::esp_reset_reason() };

    serial.line("[CRASHLOG]");
    serial.line(&format!("  Boot count: {}", boot_count));
    serial.line(&format!(
        "  This boot reason: {}",
        match reset_reason {
            1 => "POWERON",
            3 => "SW_RESET",
            4 => "PANIC",
            5 => "INT_WDT",
            6 => "TASK_WDT",
            7 => "WDT",
            8 => "DEEPSLEEP",
            9 => "BROWNOUT",
            _ => "UNKNOWN",
        }
    ));

    if let Some((reason, prev_boot)) = nvs::load_crash_info() {
        let label = match reason {
            4 => "PANIC",
            5 => "INT_WDT",
            6 => "TASK_WDT",
            7 => "WDT",
            9 => "BROWNOUT",
            _ => "UNKNOWN",
        };
        serial.line(&format!("  Last crash: {} on boot #{}", label, prev_boot));
    } else {
        serial.line("  Last crash: none");
    }
    serial.line("[CRASHLOG] END");
}

fn run_hwtest<I2C>(
    serial: &mut SerialConsole,
    buttons: &mut Option<ButtonHandler>,
    service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
) where
    I2C: embedded_hal::i2c::I2c + Send + 'static,
    I2C::Error: core::fmt::Debug,
{
    use crate::button::ButtonEvent;

    serial.line("[HWTEST] START");

    {
        let mut svc = service.lock().unwrap();
        serial.line(&format!("[HWTEST] board={BOARD_NAME}"));
        serial.line(&format!("[HWTEST] i2c_baudrate={I2C_BAUDRATE_HZ}Hz"));
        let scan = svc.i2c_scan();
        let mut scan_str = heapless::String::<128>::new();
        for &addr in scan.iter() {
            let _ = write!(scan_str, "0x{addr:02X} ");
        }
        serial.line(&format!("[HWTEST] i2c_devices={}", scan_str.trim()));
        serial.line(&format!(
            "[HWTEST] nfc={}",
            if svc.nfc_available() { "ok" } else { "missing" }
        ));
        serial.line(&format!(
            "[HWTEST] display={}",
            if DISPLAY_INIT_OK.load(Ordering::SeqCst) {
                "ok"
            } else {
                "fail"
            }
        ));
    }

    #[cfg(feature = "display-st7789")]
    {
        let mv = display::read_battery_mv();
        let usb = display::is_usb_powered();
        serial.line(&format!(
            "[HWTEST] battery={} usb={}",
            mv.map(|v| v.to_string()).unwrap_or_else(|| "none".into()),
            if usb { 1 } else { 0 }
        ));
    }

    let mode = button::get_button_mode();
    serial.line(&format!(
        "[HWTEST] button_mode={}",
        match mode {
            crate::commands::ButtonMode::Simple => "simple",
            crate::commands::ButtonMode::Legacy => "legacy",
        }
    ));

    let mut pass = 0u32;
    let mut total = 0u32;

    #[cfg(feature = "display-st7789")]
    display::set_mode(display::DisplayMode::Burn);
    #[cfg(feature = "display-st7789")]
    display::set_event("HW TEST START");

    if let Some(btns) = buttons {
        total += 2;

        serial.line("[HWTEST] STEP front_button: PRESS NOW (10s)");
        #[cfg(feature = "display-st7789")]
        display::set_event("Press FRONT btn");
        let start = millis();
        let mut detected = false;
        while millis().saturating_sub(start) < 10_000 {
            let (fe, _se) = btns.poll(millis());
            if fe != ButtonEvent::None {
                serial.line(&format!("[HWTEST]   event: {fe:?}"));
                detected = true;
                break;
            }
            FreeRtos::delay_ms(10);
        }
        if detected {
            serial.line("[HWTEST] STEP front_button: PASS");
            pass += 1;
            #[cfg(feature = "display-st7789")]
            display::set_command_result("front_btn", "PASS");
        } else {
            serial.line("[HWTEST] STEP front_button: FAIL (timeout)");
            #[cfg(feature = "display-st7789")]
            display::set_command_result("front_btn", "FAIL");
        }

        serial.line("[HWTEST] STEP side_button: PRESS NOW (10s)");
        #[cfg(feature = "display-st7789")]
        display::set_event("Press SIDE btn");
        let start = millis();
        let mut detected = false;
        while millis().saturating_sub(start) < 10_000 {
            let (_fe, se) = btns.poll(millis());
            if se != ButtonEvent::None {
                serial.line(&format!("[HWTEST]   event: {se:?}"));
                detected = true;
                break;
            }
            FreeRtos::delay_ms(10);
        }
        if detected {
            serial.line("[HWTEST] STEP side_button: PASS");
            pass += 1;
            #[cfg(feature = "display-st7789")]
            display::set_command_result("side_btn", "PASS");
        } else {
            serial.line("[HWTEST] STEP side_button: FAIL (timeout)");
            #[cfg(feature = "display-st7789")]
            display::set_command_result("side_btn", "FAIL");
        }
    } else {
        serial.line("[HWTEST] STEP buttons: SKIP (not initialized)");
    }

    total += 2;
    serial.line("[HWTEST] STEP card_tap: TAP CARD NOW (15s)");
    #[cfg(feature = "display-st7789")]
    display::set_event("Tap card now");
    let start = millis();
    let mut card_uid = None;
    while millis().saturating_sub(start) < 15_000 {
        {
            let mut svc = service.lock().unwrap();
            if let Some(assessment) = svc.poll_safe() {
                if assessment.present {
                    let mut uid_str = heapless::String::<32>::new();
                    if let Some(uid) = assessment.uid.as_ref() {
                        for &b in &uid[..assessment.uid_len as usize] {
                            let _ = write!(uid_str, "{b:02X}");
                        }
                    }
                    card_uid = Some(uid_str);
                    break;
                }
            }
        }
        FreeRtos::delay_ms(100);
    }
    match card_uid {
        Some(ref uid) => {
            serial.line(&format!("[HWTEST] STEP card_tap: PASS uid={uid}"));
            pass += 1;
            #[cfg(feature = "display-st7789")]
            display::set_command_result("card_tap", "PASS");
        }
        None => {
            serial.line("[HWTEST] STEP card_tap: FAIL (timeout)");
            #[cfg(feature = "display-st7789")]
            display::set_command_result("card_tap", "FAIL");
        }
    }

    serial.line("[HWTEST] STEP card_remove: REMOVE CARD NOW (10s)");
    #[cfg(feature = "display-st7789")]
    display::set_event("Remove card");
    let start = millis();
    let mut removed = false;
    while millis().saturating_sub(start) < 10_000 {
        {
            let mut svc = service.lock().unwrap();
            if !svc.card_present() {
                removed = true;
                break;
            }
        }
        FreeRtos::delay_ms(100);
    }
    if removed {
        serial.line("[HWTEST] STEP card_remove: PASS");
        pass += 1;
        #[cfg(feature = "display-st7789")]
        display::set_command_result("card_rm", "PASS");
    } else {
        serial.line("[HWTEST] STEP card_remove: FAIL (timeout)");
        #[cfg(feature = "display-st7789")]
        display::set_command_result("card_rm", "FAIL");
    }

    if total == pass {
        serial.line(&format!("[HWTEST] RESULT: ALL PASS ({pass}/{total})"));
        #[cfg(feature = "display-st7789")]
        {
            display::set_mode(display::DisplayMode::Idle);
            display::set_event("ALL TESTS PASS");
        }
    } else {
        serial.line(&format!("[HWTEST] RESULT: {pass}/{total} PASS"));
        #[cfg(feature = "display-st7789")]
        {
            display::set_mode(display::DisplayMode::Error);
            display::set_event(&format!("{pass}/{total} PASS"));
        }
    }
    serial.line("[HWTEST] END");
}

#[cfg(feature = "ble")]
fn process_ble_command<S: crate::service::BoltyService>(
    cmd: &str,
    service: &Arc<Mutex<S>>,
    _config: &Arc<Mutex<BoltyConfig>>,
) -> String {
    use crate::commands::{Command, parse_command};

    let Ok(mut svc) = service.lock() else {
        return "[FAIL] service unavailable".to_string();
    };

    let Ok(command) = parse_command(cmd) else {
        return format!("[FAIL] unknown command: {cmd}");
    };

    match command {
        Command::Status => {
            let status = svc.get_status();
            format!(
                "[OK] nfc={} uid={}",
                status.nfc_ready,
                status
                    .last_uid
                    .map(|u| format!("{u:02X?}"))
                    .unwrap_or_else(|| "---".into())
            )
        }
        Command::Uid => {
            let status = svc.get_status();
            format!(
                "[OK] {}",
                status
                    .last_uid
                    .map(|u| format!("{u:02X?}"))
                    .unwrap_or_else(|| "no card".into())
            )
        }
        Command::Inspect | Command::Diagnose | Command::Picc | Command::Check => {
            use crate::service::WorkflowResult;
            use crate::workflow::dispatch_command;
            let mut cfg = _config.lock().unwrap();
            match dispatch_command(command, &mut svc, &mut cfg) {
                WorkflowResult::Success => "[OK] done".to_string(),
                other => format!("[FAIL] {other:?}"),
            }
        }
        Command::Burn
        | Command::Wipe
        | Command::SetKeys(_)
        | Command::SetIssuer(_)
        | Command::SetUrl(_)
        | Command::SetToken(_) => "[FAIL] write commands blocked via BLE (issue #34)".to_string(),
        _ => "[FAIL] command not available via BLE".to_string(),
    }
}
