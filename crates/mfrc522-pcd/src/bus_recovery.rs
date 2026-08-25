//! I2C bus recovery for stuck-slave conditions.
//!
//! After a dirty reset an MFRC522 (or any I2C slave mid-transaction) can hold
//! SDA low, making every subsequent transfer time out forever. Nine SCL clock
//! pulses let the slave release the line. Run this BEFORE constructing the
//! I2C driver — bolty-rs docs/lessons-learned.md B9 (this routine used to live
//! copy-pasted in every firmware that shares this crate).

use esp_idf_sys::{
    esp_rom_delay_us, gpio_config, gpio_config_t, gpio_get_level, gpio_reset_pin, gpio_set_level,
};

const GPIO_MODE_INPUT: u32 = 1;
const GPIO_MODE_OUTPUT: u32 = 2;

fn mask(pin: i32) -> u64 {
    1u64 << pin
}

/// Recover an I2C bus whose SDA is held low by a stuck slave.
///
/// `scl_pin`/`sda_pin` are ESP32 GPIO numbers. Safe to call on a healthy bus
/// (detects SDA high and returns immediately).
pub fn recover_i2c_bus(scl_pin: i32, sda_pin: i32) {
    let sda_cfg = gpio_config_t {
        pin_bit_mask: mask(sda_pin),
        mode: GPIO_MODE_INPUT,
        pull_up_en: 1,
        pull_down_en: 0,
        intr_type: 0,
    };
    if unsafe { gpio_config(&sda_cfg) } != 0 {
        log::warn!("i2c recovery: SDA gpio_config failed");
        return;
    }
    if unsafe { gpio_get_level(sda_pin) } != 0 {
        log::debug!("i2c recovery: SDA high, bus OK");
        unsafe { gpio_reset_pin(sda_pin) };
        return;
    }
    log::warn!("i2c recovery: SDA stuck LOW, sending 9 SCL pulses");
    let scl_cfg = gpio_config_t {
        pin_bit_mask: mask(scl_pin),
        mode: GPIO_MODE_OUTPUT,
        pull_up_en: 1,
        pull_down_en: 0,
        intr_type: 0,
    };
    if unsafe { gpio_config(&scl_cfg) } != 0 {
        log::warn!("i2c recovery: SCL gpio_config failed");
        unsafe { gpio_reset_pin(sda_pin) };
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
        "i2c recovery: {}",
        if recovered {
            "SDA released OK"
        } else {
            "SDA still LOW"
        }
    );
    unsafe {
        gpio_reset_pin(scl_pin);
        gpio_reset_pin(sda_pin);
    }
}
