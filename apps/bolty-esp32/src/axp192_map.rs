//! AXP192 register map — names track the datasheet, one §cite per
//! register (hackathon-tooling `patterns/embedded/pmu-register-map.md`
//! @ ae1e378, layer 1). Kept in lockstep with the ccid-firmware-rs
//! reference implementation (`firmware/esp32-ccid/src/m5stick_lcd.rs`,
//! PR #215 branch `sisyphus/lcd-ticker-split` commits f5d5fed+02d7652):
//! same registers, same names — bolty-rs display.rs is the pattern's
//! designated consumer of this byte-locked sequence.
//!
//! `REG_CHIP_ID` (0x03, §8.3) from the ccid map has no site here — bolty
//! never probes the AXP192 chip ID — so it is not duplicated.
//!
//! Follow-up (pattern layer 2, out of scope for this change): locking
//! `init_axp192`'s write sequence as an op-table + byte lock à la ccid's
//! `AXP192_INIT_SEQUENCE` would first require restructuring the driver —
//! bolty's sequence interleaves reads (read-modify-write on REG_POWER_OUT_CTL
//! and REG_DCDC1_VOLTAGE, plus a verify read-back), which does not fit a
//! plain Set/Or table. The map itself is locked below.

// Unused on builds without `display-st7789` (e.g. board-m5atom); the map
// stays whole for cross-repo sync (same stance as display.rs `set_wifi`).
#![allow(dead_code)]

pub const REG_POWER_STATUS: u8 = 0x01; // §8.2 — VBUS bit5 = USB powered
pub const REG_DCDC1_VOLTAGE: u8 = 0x10; // §8.19 — bit2 = Grove 5V boost EXTEN
pub const REG_POWER_OUT_CTL: u8 = 0x12; // §8.5 — DCDC1|DCDC3|LDO2|LDO3|EXTEN enables
pub const REG_CHARGE_CTL1: u8 = 0x33; // §8.24 — charge target/rate
pub const REG_PEK_KEY_MODE: u8 = 0x36; // §8.28 — power-on/off timing
pub const REG_ADC_EN_1: u8 = 0x82; // §8.33 — ADC channel enables (battery telemetry)
pub const REG_GPIO0_FUNCTION: u8 = 0x90; // §8.38 — GPIO0 LDO mode
pub const REG_GPIO0_LDO_VOLTAGE: u8 = 0x91; // §8.39 — GPIO0 LDO voltage (RTC rail 3.3V on M5StickC)
pub const REG_LDO2_LDO3_VOLTAGE: u8 = 0x28; // §8.22 — hi-nibble LDO2, lo-nibble LDO3, 1.8V + 0.1V/step
pub const REG_BATT_VOLTAGE_H: u8 = 0x78; // §8.26 — battery mV, high byte
pub const REG_BATT_VOLTAGE_L: u8 = 0x79; // §8.26 — battery mV, low nibble

#[cfg(test)]
mod tests {
    use super::*;

    /// GREAT EXPECTATION lock on the register map (pattern layer 3): the
    /// addresses are load-bearing bytes of the bench-proven init sequence
    /// — names may evolve with the datasheet, values change only with a
    /// hardware re-verification. If this breaks, re-verify against the
    /// AXP192 datasheet §cites and the ccid-firmware-rs sibling map —
    /// never edit the expectations to match new unverified values.
    #[test]
    fn register_map_matches_axp192_datasheet() {
        assert_eq!(REG_POWER_STATUS, 0x01); // §8.2
        assert_eq!(REG_DCDC1_VOLTAGE, 0x10); // §8.19
        assert_eq!(REG_POWER_OUT_CTL, 0x12); // §8.5
        assert_eq!(REG_CHARGE_CTL1, 0x33); // §8.24
        assert_eq!(REG_PEK_KEY_MODE, 0x36); // §8.28
        assert_eq!(REG_ADC_EN_1, 0x82); // §8.33
        assert_eq!(REG_GPIO0_FUNCTION, 0x90); // §8.38
        // §8.39 — NOT "GPIO1 function" (the 2026-10-16 ccid mislabel the
        // sibling lock caught; bytes unchanged there, names synced here).
        assert_eq!(REG_GPIO0_LDO_VOLTAGE, 0x91);
        assert_eq!(REG_LDO2_LDO3_VOLTAGE, 0x28); // §8.22
        assert_eq!(REG_BATT_VOLTAGE_H, 0x78); // §8.26
        assert_eq!(REG_BATT_VOLTAGE_L, 0x79); // §8.26
    }

    /// A duplicate address means two names claim one register — the exact
    /// failure mode the pattern's lock exists to catch.
    #[test]
    fn register_map_addresses_are_distinct() {
        let mut map = vec![
            REG_POWER_STATUS,
            REG_DCDC1_VOLTAGE,
            REG_POWER_OUT_CTL,
            REG_CHARGE_CTL1,
            REG_PEK_KEY_MODE,
            REG_ADC_EN_1,
            REG_GPIO0_FUNCTION,
            REG_GPIO0_LDO_VOLTAGE,
            REG_LDO2_LDO3_VOLTAGE,
            REG_BATT_VOLTAGE_H,
            REG_BATT_VOLTAGE_L,
        ];
        let distinct_expected = map.len();
        map.sort_unstable();
        map.dedup();
        assert_eq!(map.len(), distinct_expected);
    }
}
