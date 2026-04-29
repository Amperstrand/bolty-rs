use core::fmt::Write as _;
use std::sync::Mutex;

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::Rgb565,
    prelude::*,
    text::{Baseline, Text},
};
use esp_idf_hal::{
    delay::Ets,
    gpio::{Gpio12, Gpio13, Gpio15, Gpio18, Gpio21, Gpio22, Gpio23, Gpio27, Gpio5, Output, PinDriver},
    i2c::{I2cConfig, I2cDriver},
    spi::{
        config::{Config, DriverConfig},
        SpiDeviceDriver, SpiDriver,
    },
    units::FromValueType,
};
use log::info;
use mipidsi::{models::ST7789, options::ColorInversion, Builder};

const LCD_H_RES: u16 = 135;
const LCD_V_RES: u16 = 240;
const DISPLAY_OFFSET_X: u16 = 52;
const DISPLAY_OFFSET_Y: u16 = 40;
const AXP192_ADDRESS: u8 = 0x34;
const SPI_BUFFER_SIZE: usize = 512;
const EVENT_LEN: usize = 22;

type LcdDisplay = mipidsi::Display<
    mipidsi::interface::SpiInterface<
        SpiDeviceDriver<'static, SpiDriver<'static>>,
        PinDriver<'static, Gpio23, Output>,
    >,
    ST7789,
    PinDriver<'static, Gpio18, Output>,
>;

struct Screen {
    display: LcdDisplay,
    state: ScreenState,
}

#[derive(Clone)]
struct ScreenState {
    board: &'static str,
    nfc_ready: bool,
    card_uid: heapless::String<16>,
    card_state: &'static str,
    wifi_ip: heapless::String<16>,
    event: heapless::String<EVENT_LEN>,
}

impl ScreenState {
    fn new(board: &'static str) -> Self {
        Self {
            board,
            nfc_ready: false,
            card_uid: heapless::String::new(),
            card_state: "none",
            wifi_ip: heapless::String::new(),
            event: heapless::String::new(),
        }
    }
}

static mut SPI_BUFFER: [u8; SPI_BUFFER_SIZE] = [0u8; SPI_BUFFER_SIZE];

static SCREEN: std::sync::Mutex<Option<Screen>> = std::sync::Mutex::new(None);

fn init_axp192(i2c: &mut I2cDriver) {
    i2c.write(AXP192_ADDRESS, &[0x28, 0xCC]).ok(); // LDO2=3.0V (backlight), LDO3=3.0V (display)
    let mut buf = [0u8; 1];
    i2c.write_read(AXP192_ADDRESS, &[0x12], &mut buf).ok(); // read power control
    i2c.write(AXP192_ADDRESS, &[0x12, buf[0] | 0x4D]).ok(); // enable DCDC1, LDO2, LDO3, EXTEN
    i2c.write(AXP192_ADDRESS, &[0x82, 0xFF]).ok(); // ADC all enabled
    i2c.write(AXP192_ADDRESS, &[0x33, 0xC0]).ok(); // charge 4.2V, 100mA
    i2c.write(AXP192_ADDRESS, &[0x36, 0x0C]).ok(); // 128ms poweron, 4s poweroff
    i2c.write(AXP192_ADDRESS, &[0x91, 0xF0]).ok(); // RTC 3.3V
    i2c.write(AXP192_ADDRESS, &[0x90, 0x02]).ok(); // GPIO0 → LDO mode
    info!("AXP192 PMU initialized");
}

/// # Safety: call exactly once at startup. SPI_BUFFER is handed to the display driver permanently.
pub unsafe fn init(
    i2c1: esp_idf_hal::i2c::I2C1<'static>,
    spi2: esp_idf_hal::spi::SPI2<'static>,
    pin_sda: Gpio21,
    pin_scl: Gpio22,
    pin_sclk: Gpio13,
    pin_mosi: Gpio15,
    pin_dc: Gpio23,
    pin_rst: Gpio18,
    pin_bl: Gpio27,
    board: &'static str,
) -> Result<(), &'static str> {
    let mut axp = I2cDriver::new(i2c1, pin_sda, pin_scl, &I2cConfig::new().baudrate(400.kHz().Hz()))
        .map_err(|e| { log::error!("AXP192 I2C1 init failed: {e:?}"); "axp192 i2c failed" })?;
    init_axp192(&mut axp);
    Ets.delay_ms(100);
    drop(axp);

    let spi_driver = SpiDriver::new(spi2, pin_sclk, pin_mosi, None::<Gpio12>, &DriverConfig::new())
        .map_err(|e| { log::error!("SPI2 init failed: {e:?}"); "spi2 failed" })?;

    let spi_device = SpiDeviceDriver::new(
        spi_driver,
        None::<Gpio5>,
        &Config::new().baudrate(20.MHz().into()),
    )
    .map_err(|e| { log::error!("SPI2 device failed: {e:?}"); "spi2 device failed" })?;

    let dc = PinDriver::output(pin_dc)
        .map_err(|e| { log::error!("DC pin failed: {e:?}"); "dc pin failed" })?;
    let rst = PinDriver::output(pin_rst)
        .map_err(|e| { log::error!("RST pin failed: {e:?}"); "rst pin failed" })?;
    let mut backlight = PinDriver::output(pin_bl)
        .map_err(|e| { log::error!("BL pin failed: {e:?}"); "bl pin failed" })?;

    let buffer = &mut SPI_BUFFER;
    let di = mipidsi::interface::SpiInterface::new(spi_device, dc, buffer);

    let mut display = Builder::new(ST7789, di)
        .display_size(LCD_H_RES, LCD_V_RES)
        .display_offset(DISPLAY_OFFSET_X, DISPLAY_OFFSET_Y)
        .invert_colors(ColorInversion::Inverted)
        .reset_pin(rst)
        .init(&mut Ets)
        .map_err(|e| { log::error!("Display init failed: {e:?}"); "display init failed" })?;

    display.clear(Rgb565::BLACK).map_err(|e| {
        log::error!("Display clear failed: {e:?}"); "clear failed"
    })?;
    backlight.set_high().map_err(|e| {
        log::error!("Backlight failed: {e:?}"); "backlight failed"
    })?;

    info!("ST7789 display initialized ({}x{})", LCD_H_RES, LCD_V_RES);

    *SCREEN.lock().unwrap() = Some(Screen {
        display,
        state: ScreenState::new(board),
    });

    Ok(())
}

fn with_screen<F: FnOnce(&mut Screen)>(f: F) {
    if let Ok(mut guard) = SCREEN.lock() {
        if let Some(screen) = guard.as_mut() {
            f(screen);
        }
    }
}

fn redraw(screen: &mut Screen) {
    let state = &screen.state;
    let display = &mut screen.display;
    let _ = display.clear(Rgb565::BLACK);

    let green = MonoTextStyleBuilder::new().font(&FONT_6X10).text_color(Rgb565::GREEN).build();
    let gray = MonoTextStyleBuilder::new().font(&FONT_6X10).text_color(Rgb565::CSS_GRAY).build();
    let yellow = MonoTextStyleBuilder::new().font(&FONT_6X10).text_color(Rgb565::YELLOW).build();
    let red = MonoTextStyleBuilder::new().font(&FONT_6X10).text_color(Rgb565::RED).build();

    let lh = 12i32;
    let x = 2i32;

    let mut l1 = heapless::String::<32>::new();
    let _ = write!(l1, "{} NFC:{}", state.board, if state.nfc_ready { "OK" } else { "--" });
    let _ = Text::with_baseline(&l1, Point::new(x, lh), green, Baseline::Top).draw(display);

    let mut l2 = heapless::String::<32>::new();
    if state.card_uid.is_empty() {
        let _ = write!(l2, "UID: ---");
        let _ = Text::with_baseline(&l2, Point::new(x, 2 * lh), gray, Baseline::Top).draw(display);
    } else {
        let _ = write!(l2, "UID: {}", state.card_uid);
        let _ = Text::with_baseline(&l2, Point::new(x, 2 * lh), yellow, Baseline::Top).draw(display);
    }

    let mut l3 = heapless::String::<24>::new();
    let _ = write!(l3, "State: {}", state.card_state);
    let s3 = match state.card_state {
        "blank" | "none" => gray,
        "provisioned" => yellow,
        _ => red,
    };
    let _ = Text::with_baseline(&l3, Point::new(x, 3 * lh), s3, Baseline::Top).draw(display);

    let mut l4 = heapless::String::<32>::new();
    if state.wifi_ip.is_empty() {
        let _ = write!(l4, "WiFi: ---");
        let _ = Text::with_baseline(&l4, Point::new(x, 4 * lh), gray, Baseline::Top).draw(display);
    } else {
        let _ = write!(l4, "WiFi: {}", state.wifi_ip);
        let _ = Text::with_baseline(&l4, Point::new(x, 4 * lh), yellow, Baseline::Top).draw(display);
    }

    if !state.event.is_empty() {
        let max = (LCD_H_RES as usize) / 6;
        let txt = if state.event.len() > max { &state.event[..max] } else { state.event.as_str() };
        let _ = Text::with_baseline(txt, Point::new(x, 5 * lh), green, Baseline::Top).draw(display);
    }

    let mut footer = heapless::String::<24>::new();
    let _ = write!(footer, "bolty v{}", env!("CARGO_PKG_VERSION"));
    let _ = Text::with_baseline(&footer, Point::new(x, (LCD_V_RES as i32) - lh - 2), gray, Baseline::Top).draw(display);
}

pub fn set_nfc_ready(ready: bool) {
    with_screen(|s| { s.state.nfc_ready = ready; redraw(s); });
}

pub fn set_card(uid: &str, state: &'static str) {
    with_screen(|s| {
        s.state.card_uid.clear();
        let _ = s.state.card_uid.push_str(uid);
        s.state.card_state = state;
        redraw(s);
    });
}

pub fn clear_card() {
    with_screen(|s| {
        s.state.card_uid.clear();
        s.state.card_state = "none";
        redraw(s);
    });
}

pub fn set_wifi(ip: &str) {
    with_screen(|s| {
        s.state.wifi_ip.clear();
        let _ = s.state.wifi_ip.push_str(ip);
        redraw(s);
    });
}

pub fn clear_wifi() {
    with_screen(|s| {
        s.state.wifi_ip.clear();
        redraw(s);
    });
}

pub fn set_event(event: &str) {
    with_screen(|s| {
        s.state.event.clear();
        let _ = s.state.event.push_str(event);
        redraw(s);
    });
}
