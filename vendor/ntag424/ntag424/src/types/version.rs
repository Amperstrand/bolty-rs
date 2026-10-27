// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// Software, hardware, and production information about the tag.
///
/// See [Session](`crate::Session::get_version`) for how to obtain this information from the tag.
#[derive(Debug)]
pub struct Version {
    pub(crate) part1: [u8; 7],
    pub(crate) part2: [u8; 7],
    // Byte 15 is optional, present for customized configurations when FabKey = 1Fh
    pub(crate) part3: [u8; 14],
}

impl Version {
    // Part 1 - Hardware related information

    /// Hardware vendor ID (`VendorID`). Expected value: `0x04` (NXP Semiconductors).
    pub fn hw_vendor_id(&self) -> u8 {
        self.part1[0]
    }

    /// Hardware type (`HWType`). Expected value: `0x04` (HW type for NTAG).
    pub fn hw_type(&self) -> u8 {
        self.part1[1]
    }

    /// Hardware subtype (`HWSubType`). Encodes antenna capacitance, Tag Tamper
    /// support, and back modulation strength:
    ///
    /// | Value | Meaning |
    /// |-------|---------|
    /// | `X8h` | 50 pF antenna + Tag Tamper capable |
    /// | `0Xh` | Strong back modulation |
    /// | `8Xh` | Standard back modulation |
    ///
    /// Also see [`has_tag_tamper_support`](`Self::has_tag_tamper_support`),
    /// which uses the low nibble of this field.
    pub fn hw_sub_type(&self) -> u8 {
        self.part1[2]
    }

    /// Returns whether the hardware subtype indicates Tag Tamper-capable silicon.
    pub fn has_tag_tamper_support(&self) -> bool {
        self.hw_sub_type() & 0x0F == 0x08
    }

    /// Hardware major version number (`HWMajorVersion`). Expected value: `0x30`.
    pub fn hw_major_version(&self) -> u8 {
        self.part1[3]
    }

    /// Hardware minor version number (`HWMinorVersion`). Expected value: `0x00`.
    pub fn hw_minor_version(&self) -> u8 {
        self.part1[4]
    }

    /// Hardware storage size (`HWStorageSize`). `0x11` = 256 B < storage size < 512 B;
    /// other values are RFU.
    pub fn hw_storage_size(&self) -> u8 {
        self.part1[5]
    }

    /// Hardware communication protocol type (`HWProtocol`). Expected value: `0x05`.
    pub fn hw_protocol_type(&self) -> u8 {
        self.part1[6]
    }

    // Part 2 - Software related information

    /// Software vendor ID (`VendorID`). Expected value: `0x04` (NXP Semiconductors).
    pub fn sw_vendor_id(&self) -> u8 {
        self.part2[0]
    }

    /// Software type (`SWType`). Expected value: `0x04` (SW type for NTAG).
    pub fn sw_type(&self) -> u8 {
        self.part2[1]
    }

    /// Software subtype (`SWSubType`). Expected value: `0x02`.
    pub fn sw_sub_type(&self) -> u8 {
        self.part2[2]
    }

    /// Software major version number (`SWMajorVersion`). Expected value: `0x01`.
    pub fn sw_major_version(&self) -> u8 {
        self.part2[3]
    }

    /// Software minor version number (`SWMinorVersion`). Expected value: `0x02`.
    pub fn sw_minor_version(&self) -> u8 {
        self.part2[4]
    }

    /// Software storage size (`SWStorageSize`). `0x11` = 256 B < storage size < 512 B;
    /// other values are RFU.
    pub fn sw_storage_size(&self) -> u8 {
        self.part2[5]
    }

    /// Software communication protocol type (`SWProtocol`). Expected value: `0x05`.
    pub fn sw_protocol_type(&self) -> u8 {
        self.part2[6]
    }

    // Part 3 - Production related information

    /// The 7-byte UID of the tag. For tags in random-ID mode, this is the
    /// randomized ID.
    ///
    /// Use [`AuthenticatedSession::get_uid`](`crate::AuthenticatedSession::get_uid`) to obtain the real UID on random-ID tags.
    pub fn uid(&self) -> &[u8; 7] {
        // TODO: clarify padding for random ID which are shorter
        // TODO: reference `get_uid` for real UID on random-ID tags once implemented
        self.part3
            .first_chunk::<7>()
            .expect("part3 is at least 7 bytes")
    }

    /// Production batch number (`BatchNo`).
    pub fn batch_number(&self) -> u32 {
        let batch = self.part3[7..]
            .first_chunk::<4>()
            .expect("part3 is at least 11 bytes");
        u32::from_be_bytes(*batch)
    }

    /// Calendar week of production.
    pub fn calendar_week_of_production(&self) -> u8 {
        // Bit 7 of the raw byte is the DefaultFabKey flag; bits 6-0 are the BCD week,
        // NT3H2421Gx §10.5.2, Table 58.
        bcd_decode(self.part3[12] & 0b0111_1111)
    }

    // pub fn default_fab_key(&self) -> bool {
    //     self.part3[12] & 0b0100_0000 != 0
    // }

    /// Calendar year of production as the last two decimal digits.
    ///
    /// For example 26 corresponds to year 2026.
    pub fn calendar_year_of_production(&self) -> u8 {
        bcd_decode(self.part3[13])
    }

    pub fn is_ntag_424(&self) -> bool {
        if !(self.hw_vendor_id() == 0x04 && self.hw_type() == 0x04) {
            return false;
        }
        let sub_type = self.hw_sub_type();
        if !matches!(sub_type & 0x0F, 0x08 | 0x02) {
            return false;
        }
        if !matches!(sub_type & 0xF0, 0x00 | 0x80) {
            return false;
        }
        if self.hw_major_version() != 0x30 || self.hw_minor_version() != 0x00 {
            return false;
        }
        if self.hw_storage_size() != 0x11 {
            return false;
        }
        if self.hw_protocol_type() != 0x05 {
            return false;
        }
        if self.sw_vendor_id() != 0x04 || self.sw_type() != 0x04 || self.sw_sub_type() != 0x02 {
            return false;
        }
        if self.sw_major_version() != 0x01 || self.sw_minor_version() != 0x02 {
            return false;
        }
        if self.sw_storage_size() != 0x11 {
            return false;
        }
        if self.sw_protocol_type() != 0x05 {
            return false;
        }
        true
    }
}

/// Decode a BCD-encoded byte into its decimal value (e.g. `0x26` → `26`).
fn bcd_decode(byte: u8) -> u8 {
    (byte >> 4) * 10 + (byte & 0x0F)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_with_hw_sub_type(hw_sub_type: u8) -> Version {
        Version {
            part1: [0x00, 0x00, hw_sub_type, 0x00, 0x00, 0x00, 0x00],
            part2: [0x00; 7],
            part3: [0x00; 14],
        }
    }

    #[test]
    fn tag_tamper_detection_accepts_both_back_modulation_variants() {
        assert!(version_with_hw_sub_type(0x08).has_tag_tamper_support());
        assert!(version_with_hw_sub_type(0x88).has_tag_tamper_support());
    }

    #[test]
    fn tag_tamper_detection_rejects_non_tt_low_nibbles() {
        assert!(!version_with_hw_sub_type(0x02).has_tag_tamper_support());
        assert!(!version_with_hw_sub_type(0x82).has_tag_tamper_support());
    }

    #[test]
    fn tag_tamper_detection_looks_at_the_x8h_suffix_not_the_high_nibble() {
        assert!(version_with_hw_sub_type(0x08).has_tag_tamper_support());
        assert!(!version_with_hw_sub_type(0x80).has_tag_tamper_support());
    }
}
