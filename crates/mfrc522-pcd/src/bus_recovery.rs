//! I2C bus recovery for stuck-slave conditions.
//!
//! Implements the full stuck-bus procedure from NXP AN10217 (I2C-bus
//! specification, "bus clear") and TI SLVA704:
//!   1. Clock SCL until the slave releases SDA (cap: [`MAX_CLOCKS`]).
//!   2. Generate a STOP condition so the slave's state machine returns to idle.
//! A slave interrupted mid-transaction holds SDA low until it has been clocked
//! past its pending bit(s); a multi-byte burst can need more than the classic
//! 9 clocks, and without the trailing STOP a released slave may re-assert.
//!
//! Run this BEFORE constructing the I2C driver — never while one exists: the
//! raw GPIO calls steal the pins from the I2C controller.
//!
//! What software CANNOT clear ([`BusRecovery::StillStuck`]): if SDA stays low
//! after [`MAX_CLOCKS`] + STOP, the line cannot rise at all — that is an
//! electrical condition (SDA shorted to GND, or slave latch-up: a parasitic
//! SCR conducting on the die, where no register is reachable because the chip
//! is not logically alive). Only removing reader power clears latch-up; a
//! short needs wire work. Deliberately rejected: driving SDA high push-pull
//! to "force" release — I2C is open-drain, pushing 3V3 into a slave's output
//! FET while it sinks can damage it. Next-rig hardware fix: load switch (or
//! FET) on reader VCC, or use a breakout exposing the MFRC522 NRSTPD pin.

use esp_idf_sys::{
    esp_rom_delay_us, gpio_config, gpio_config_t, gpio_get_level, gpio_reset_pin, gpio_set_level,
};

const GPIO_MODE_INPUT: u32 = 1;
const GPIO_MODE_OUTPUT: u32 = 2;

const MAX_CLOCKS: u32 = 32;
const HALF_PERIOD_US: u32 = 10;

fn mask(pin: i32) -> u64 {
    1u64 << pin
}

/// Outcome of a bus-recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusRecovery {
    /// SDA already high — bus was idle, nothing was clocked.
    AlreadyIdle,
    /// SDA released after `clocks` SCL pulses; STOP sent and acknowledged by
    /// the release (SDA high with SCL high).
    Recovered { clocks: u32 },
    /// SDA still low after MAX_CLOCKS — electrical fault (short or latch-up);
    /// power-cycle the reader or repair the wiring. Not software-clearable.
    StillStuck,
}

fn pin_as(pin: i32, mode: u32, pull_up: bool) -> bool {
    let cfg = gpio_config_t {
        pin_bit_mask: mask(pin),
        mode,
        pull_up_en: u32::from(pull_up),
        pull_down_en: 0,
        intr_type: 0,
    };
    unsafe { gpio_config(&cfg) == 0 }
}

/// Recover an I2C bus whose SDA is held low by a stuck slave.
///
/// `scl_pin`/`sda_pin` are ESP32 GPIO numbers. Safe to call on a healthy bus
/// (detects SDA high and returns without clocking).
pub fn recover_i2c_bus(scl_pin: i32, sda_pin: i32) -> BusRecovery {
    if !pin_as(sda_pin, GPIO_MODE_INPUT, true) {
        log::warn!("i2c recovery: SDA gpio_config failed");
        return BusRecovery::StillStuck;
    }
    if unsafe { gpio_get_level(sda_pin) } != 0 {
        log::debug!("i2c recovery: SDA high, bus OK");
        unsafe { gpio_reset_pin(sda_pin) };
        return BusRecovery::AlreadyIdle;
    }

    log::warn!("i2c recovery: SDA stuck LOW — clocking SCL until release (max {MAX_CLOCKS})");
    if !pin_as(scl_pin, GPIO_MODE_OUTPUT, true) {
        log::warn!("i2c recovery: SCL gpio_config failed");
        unsafe { gpio_reset_pin(sda_pin) };
        return BusRecovery::StillStuck;
    }

    let mut clocks: u32 = 0;
    while clocks < MAX_CLOCKS {
        unsafe {
            gpio_set_level(scl_pin, 1);
            esp_rom_delay_us(HALF_PERIOD_US);
        }
        clocks += 1;
        if unsafe { gpio_get_level(sda_pin) } != 0 {
            break;
        }
        unsafe {
            gpio_set_level(scl_pin, 0);
            esp_rom_delay_us(HALF_PERIOD_US);
        }
    }

    let released = unsafe { gpio_get_level(sda_pin) } != 0;
    let outcome = if released && stop_condition(scl_pin, sda_pin) {
        log::info!("i2c recovery: SDA released after {clocks} clocks + STOP — bus clear");
        BusRecovery::Recovered { clocks }
    } else {
        log::error!(
            "i2c recovery: SDA still LOW after {MAX_CLOCKS} clocks — electrical fault \
             (short or slave latch-up); power-cycle the reader, software cannot clear this"
        );
        BusRecovery::StillStuck
    };

    unsafe {
        gpio_reset_pin(scl_pin);
        gpio_reset_pin(sda_pin);
    }
    outcome
}

/// STOP condition: with SCL high, SDA transitions low → high.
/// Returns true if SDA reads high afterwards.
fn stop_condition(scl_pin: i32, sda_pin: i32) -> bool {
    if !pin_as(sda_pin, GPIO_MODE_OUTPUT, true) {
        return false;
    }
    unsafe {
        gpio_set_level(scl_pin, 0);
        esp_rom_delay_us(HALF_PERIOD_US);
        gpio_set_level(sda_pin, 0);
        esp_rom_delay_us(HALF_PERIOD_US);
        gpio_set_level(scl_pin, 1);
        esp_rom_delay_us(HALF_PERIOD_US);
        gpio_set_level(sda_pin, 1);
        esp_rom_delay_us(HALF_PERIOD_US);
        let ok = gpio_get_level(sda_pin) != 0 && gpio_get_level(scl_pin) != 0;
        log::debug!("i2c recovery: STOP sent, lines high: {ok}");
        ok
    }
}
