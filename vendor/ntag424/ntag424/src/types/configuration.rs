// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Configuration payloads for the `SetConfiguration` command (NT4H2421Gx
//! §10.5.1, Tables 49 and 50).

use super::file_settings::Access;

/// Builder for the [`AuthenticatedSession::set_configuration`](`crate::AuthenticatedSession::set_configuration`) argument.
///
/// Each option (PICC, secure messaging, capability, Tag Tamper,
/// failed-authentication counter, HW) is independent and only emitted on the
/// wire if the caller explicitly set it through one of the `with_*` methods.
/// Unset options are omitted, so the corresponding tag-side configuration
/// stays unchanged.
///
/// **Last-writer-wins:** each `with_*` method unconditionally overwrites any
/// previous value for that option. Calling `with_failed_auth_counter_enabled`
/// followed by `with_failed_auth_counter_disabled` results in disabled — the
/// second call silently replaces the first.
#[derive(Debug, Default, Clone)]
pub struct Configuration {
    picc: Option<[u8; 1]>,
    secure_messaging: Option<[u8; 2]>,
    capability: Option<[u8; 10]>,
    tag_tamper: Option<[u8; 2]>,
    failed_auth_counter: Option<[u8; 5]>,
    hw: Option<[u8; 1]>,
}

impl Configuration {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable Random UID mode (PICCConfig bit 1).
    ///
    /// <div class="warning">This change is <strong>permanent</strong>.</div>
    ///
    /// Depending on tag usage this feature may help to fulfill GDPR regulations
    /// regarding personal tracking and personal data.
    ///
    /// If you use [derived keys](`crate::key_diversification`) based on the UID, be aware that
    /// you can no longer read the real UID _before_ authentication, which
    /// should be considered in your key diversification and provisioning strategy.
    pub fn with_random_uid_enabled(mut self) -> Self {
        // TODO: extend docs, briefly explain the consequences
        let bytes = self.picc.get_or_insert([0]);
        bytes[0] |= 1 << 1;
        self
    }

    /// Disable chained writes.
    ///
    /// <div class="warning">This change is <strong>permanent</strong>.</div>
    ///
    /// Sets SMConfig bit 2 for `WriteData` in `CommMode.MAC` and
    /// `CommMode.Full`.
    pub fn with_chained_writing_disabled(mut self) -> Self {
        // TODO: extend docs, briefly explain the consequences
        let bytes = self.secure_messaging.get_or_insert([0; 2]);
        // SMConfig is two bytes; bit 2 lives in the low byte.
        bytes[0] |= 1 << 2;
        self
    }

    /// Enable LRP (Leakage Resilient Primitive) mode (PDCap2.1 bit 1).
    ///
    /// This change is **permanent** - once enabled, LRP cannot be disabled
    /// (NT4H2421Gx §8, "After this switch, it is not possible to revert back
    /// to AES mode").
    ///
    /// The switch is exposed only to the crate because it must not be mixed
    /// with other `SetConfiguration` options: enabling LRP tears down the
    /// current secure channel on the PICC (the PICC returns `9100` without
    /// a response `MACt`, and any subsequent secure-messaging command fails
    /// with `LENGTH_ERROR` / `PERMISSION_DENIED`). Callers go through
    /// `Session<Authenticated<AesSuite>>::enable_lrp`, which performs the
    /// single-option APDU and yields a fresh unauthenticated session.
    ///
    /// AES vs. LRP is negotiated only on First Authentication via
    /// `PCDCap2.1` / `PDCap2.1` (NT4H2421Gx §9.1.4, Table 19); after the
    /// session is reset the PICC rejects `AuthenticateEV2First` with
    /// `PERMISSION_DENIED` and only accepts `AuthenticateLRPFirst`.
    pub(crate) fn with_lrp_enabled(mut self) -> Self {
        let bytes = self.capability.get_or_insert([0; 10]);
        bytes[4] |= 1 << 1;
        self
    }

    /// Set the user-configured `PDCap2.5` capability byte.
    ///
    /// Is sent during first authentication and can be read using [`crate::AuthenticatedSession::pcd_cap2`].
    pub fn with_pdcap2_5(mut self, byte: u8) -> Self {
        let bytes = self.capability.get_or_insert([0; 10]);
        bytes[8] = byte;
        self
    }

    /// Set the user-configured `PDCap2.6` capability byte.
    ///
    /// Is sent during first authentication and can be read using [`crate::AuthenticatedSession::pcd_cap2`].
    pub fn with_pdcap2_6(mut self, byte: u8) -> Self {
        let bytes = self.capability.get_or_insert([0; 10]);
        bytes[9] = byte;
        self
    }

    /// Enable Tag Tamper and configure who may call `GetTTStatus`.
    ///
    /// <div class="warning">This change is <strong>permanent</strong>.</div>
    ///
    /// Once enabled on a Tag Tamper-capable chip, the feature cannot be
    /// disabled again. Measurements start from the next activation onward.
    pub fn with_tag_tamper_enabled(mut self, status_access: Access) -> Self {
        let status_access = match status_access {
            Access::Key(key) => key.as_byte(),
            Access::Free => 0x0E,
            Access::NoAccess => 0x0F,
        };
        self.tag_tamper = Some([0x01, status_access]);
        self
    }

    /// Enable the failed-authentication counter.
    ///
    /// `limit` must be non-zero (tag default: 1000); `decrement` is the amount
    /// subtracted from `limit` on each successful authentication (tag default: 10).
    pub fn with_failed_auth_counter_enabled(mut self, limit: u16, decrement: u16) -> Self {
        let mut bytes = [0u8; 5];
        bytes[0] = 1;
        bytes[1..3].copy_from_slice(&limit.to_le_bytes());
        bytes[3..5].copy_from_slice(&decrement.to_le_bytes());
        self.failed_auth_counter = Some(bytes);
        self
    }

    /// Disable the failed-authentication counter.
    pub fn with_failed_auth_counter_disabled(mut self) -> Self {
        self.failed_auth_counter = Some([0u8; 5]);
        self
    }

    /// Configure HW back modulation: `true` for Strong (factory default),
    /// `false` for Standard. The datasheet recommends keeping the default for
    /// antennas smaller than Class 1.
    pub fn with_strong_back_modulation(mut self, strong: bool) -> Self {
        self.hw = Some([u8::from(strong)]);
        self
    }

    /// Iterate over configured options in wire order.
    ///
    /// Yields `(option_id, payload)` pairs in the canonical Table 50
    /// order. Options that were never set are skipped.
    pub(crate) fn build(&self) -> impl Iterator<Item = (u8, &[u8])> {
        [
            (0x00u8, self.picc.as_ref().map(|b| b.as_slice())),
            (0x04, self.secure_messaging.as_ref().map(|b| b.as_slice())),
            (0x05, self.capability.as_ref().map(|b| b.as_slice())),
            (0x07, self.tag_tamper.as_ref().map(|b| b.as_slice())),
            (
                0x0A,
                self.failed_auth_counter.as_ref().map(|b| b.as_slice()),
            ),
            (0x0B, self.hw.as_ref().map(|b| b.as_slice())),
        ]
        .into_iter()
        .filter_map(|(id, data)| data.map(|d| (id, d)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyNumber;

    #[test]
    fn tag_tamper_builder_emits_option_07_payload() {
        let built: alloc::vec::Vec<_> = Configuration::new()
            .with_tag_tamper_enabled(Access::Key(KeyNumber::Key4))
            .build()
            .map(|(id, data)| (id, data.to_vec()))
            .collect();

        assert_eq!(built, alloc::vec![(0x07, alloc::vec![0x01, 0x04])]);
    }

    #[test]
    fn build_emits_tag_tamper_in_table_50_order() {
        let option_ids: alloc::vec::Vec<_> = Configuration::new()
            .with_failed_auth_counter_enabled(1000, 10)
            .with_tag_tamper_enabled(Access::NoAccess)
            .with_pdcap2_5(0xAA)
            .with_random_uid_enabled()
            .build()
            .map(|(id, _)| id)
            .collect();

        assert_eq!(option_ids, alloc::vec![0x00, 0x05, 0x07, 0x0A]);
    }
}
