use std::sync::{Arc, Mutex};

use bolty_core::{
    config::BoltyConfig,
    service::{BoltyService, WorkflowResult},
};
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

#[cfg(feature = "display-st7789")]
use crate::display;
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

#[cfg(not(feature = "wifi"))]
struct WifiManager;

#[cfg(feature = "board-m5atom")]
const BOARD_NAME: &str = "M5Atom";
#[cfg(feature = "board-m5stick")]
const BOARD_NAME: &str = "M5StickC Plus";

pub(super) const RND_A: [u8; 16] = [0u8; 16];
const I2C_BAUDRATE_HZ: u32 = 400_000;
pub(super) const MAX_LINE_LEN: usize = 512;
pub(super) const SERIAL_FD_IN: i32 = 0;
pub(super) const SERIAL_FD_OUT: i32 = 1;
const CARD_POLL_INTERVAL_MS: u64 = 500;
const MAIN_LOOP_DELAY_MS: u32 = 10;
#[cfg(feature = "rest")]
pub(super) const REST_PORT: u16 = 80;

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
        if let Err(e) = result {
            log::error!("Display init failed: {e}");
        }
    }

    #[cfg(feature = "board-m5atom")]
    let (i2c_sda, i2c_scl) = (peripherals.pins.gpio26, peripherals.pins.gpio32);
    #[cfg(feature = "board-m5stick")]
    let (i2c_sda, i2c_scl) = (peripherals.pins.gpio32, peripherals.pins.gpio33);

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
    let initial_config = BoltyConfig::default();
    let config = Arc::new(Mutex::new(initial_config.clone()));
    let service = Arc::new(Mutex::new(Esp32BoltyService::new(
        xcvr,
        raw_i2c,
        initial_i2c_scan,
        initial_config,
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
    let mut card_announced = false;

    info!("=== Bolty Ready ===");
    print_boot_banner(&mut serial);

    #[cfg(feature = "display-st7789")]
    display::set_event("ready");

    loop {
        while let Some(byte) = serial.read_byte_nonblocking() {
            match byte {
                b'\r' => {}
                b'\n' => {
                    if !line.is_empty() {
                        handle_line(
                            &mut serial,
                            line.as_str(),
                            &service,
                            &config,
                            &mut wifi_manager,
                            #[cfg(feature = "rest")]
                            &mut rest_server,
                        );
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

        let now = millis();
        if now >= next_poll_at {
            poll_card(&mut serial, &service, &mut card_announced);
            next_poll_at = now.saturating_add(CARD_POLL_INTERVAL_MS);
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

    match service.check_blank() {
        WorkflowResult::CardNotPresent => {
            *card_announced = false;
            #[cfg(feature = "display-st7789")]
            display::clear_card();
        }
        WorkflowResult::Success | WorkflowResult::Error(_) => {
            if !*card_announced && service.last_card.present {
                serial.card(&service.last_card);
                *card_announced = true;
                #[cfg(feature = "display-st7789")]
                {
                    let mut uid_hex = heapless::String::<16>::new();
                    if let Some(uid) = service.last_card.uid.as_ref() {
                        let _ =
                            push_uid_hex(&mut uid_hex, &uid[..service.last_card.uid_len as usize]);
                    }
                    display::set_card(uid_hex.as_str(), card_state_label(service.last_card.state));
                }
            }
        }
        WorkflowResult::AuthFailed | WorkflowResult::AuthDelay | WorkflowResult::WipeRefused => {
            if !*card_announced && service.last_card.present {
                serial.card(&service.last_card);
                *card_announced = true;
                #[cfg(feature = "display-st7789")]
                {
                    let mut uid_hex = heapless::String::<16>::new();
                    if let Some(uid) = service.last_card.uid.as_ref() {
                        let _ =
                            push_uid_hex(&mut uid_hex, &uid[..service.last_card.uid_len as usize]);
                    }
                    display::set_card(uid_hex.as_str(), card_state_label(service.last_card.state));
                }
            }
        }
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
    // Fallback if esp_restart somehow returns (should not happen).
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
