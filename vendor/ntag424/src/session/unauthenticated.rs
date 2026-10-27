// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

#[cfg(feature = "originality")]
use crate::{
    TagTamperStatus,
    types::{cc::CapabilityContainer, file_settings::CryptoMode},
};

use super::*;

/// Max bytes per single `ISOReadBinary` APDU.
///
/// `Le` is one byte; `Le = 00h` requests the short-form maximum of 256
/// bytes (NT4H2421Gx §10.9.2). Reads larger than the per-APDU cap are
/// chunked across successive offsets.
const ISO_READ_BINARY_CHUNK: usize = 256;

/// Max bytes per single `ISOUpdateBinary` APDU.
///
/// `Lc` is one byte; the maximum body is 255 bytes (no secure-messaging
/// overhead — `ISOUpdateBinary` is `CommMode.Plain` only). Writes larger
/// than the per-APDU cap are chunked across successive offsets.
const ISO_UPDATE_BINARY_CHUNK: usize = 255;

pub struct Unauthenticated;

impl Session<Unauthenticated> {
    /// Initialize a new unauthenticated session.
    pub fn new() -> Self {
        Self {
            state: Unauthenticated,
            ndef_selected: false,
            ef_selected: None,
        }
    }
}

impl Default for Session<Unauthenticated> {
    fn default() -> Self {
        Self::new()
    }
}

impl Session<Unauthenticated> {
    /// Select the NDEF application by DF name.
    ///
    /// After power-on the tag starts at the MF (master file) level where
    /// ISO file commands and authentication are not reachable.
    /// Call this once per transport session before any `read_unauthenticated`
    /// or authentication call (NT4H2421Gx §8.2.1).
    ///
    /// Only exposed on an unauthenticated session: re-selecting the
    /// application terminates any active authenticated state, so doing so
    /// silently through a `Session<Authenticated<_>>` would desynchronize
    /// the tracked session keys and command counter.
    pub(crate) async fn select_ndef_application<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), SessionError<T::Error>> {
        if self.ndef_selected {
            return Ok(());
        }
        select_ndef_application(transport).await?;
        self.ndef_selected = true;
        self.ef_selected = None;
        Ok(())
    }

    /// Read bytes from a file.
    ///
    /// The command is using plain mode.
    /// Read access on the targeted file must
    /// be set to [free access](`crate::types::file_settings::Access::Free`) for the call to succeed.
    ///
    /// For files with other access conditions, authentication may be required and
    /// the caller should use [`AuthenticatedSession::read_file_with_mode`].
    ///
    /// Buffers larger than the per-APDU cap of 256 bytes are split into
    /// multiple `ISOReadBinary` APDUs at successive 15-bit offsets — the
    /// EF stays selected across calls. The returned `usize` is the
    /// number of bytes actually copied into `buf`; it can be smaller than
    /// `buf.len()` if the PICC reports the end of the file with a short
    /// payload, in which case no further APDUs are issued.
    pub async fn read_file_unauthenticated<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u16,
        buf: &mut [u8],
    ) -> Result<usize, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        if self.ef_selected != Some(file.file_id()) {
            iso_select_ef_by_fid(transport, file.file_id()).await?;
            self.ef_selected = Some(file.file_id());
        }

        if buf.is_empty() {
            // Surface the empty-buffer error from `iso_read_binary`.
            return iso_read_binary(transport, None, offset, buf).await;
        }

        let mut total: usize = 0;
        while total < buf.len() {
            let want = (buf.len() - total).min(ISO_READ_BINARY_CHUNK);
            let abs = offset as usize + total;
            if abs > 0x7FFF {
                return Err(SessionError::InvalidCommandParameter {
                    parameter: "offset",
                    value: abs,
                    reason: "must be <= 0x7FFF",
                });
            }
            let n =
                iso_read_binary(transport, None, abs as u16, &mut buf[total..total + want]).await?;
            total += n;
            if n < want {
                // PICC returned a short payload — file boundary reached.
                break;
            }
        }
        Ok(total)
    }

    /// Write bytes to a file.
    ///
    /// The command is using plain mode.
    /// Write access on the targeted file
    /// must be set to [free access](`crate::types::file_settings::Access::Free`) for the call to succeed.
    ///
    /// Inputs larger than the per-APDU cap of 255 bytes are split into
    /// multiple `ISOUpdateBinary` APDUs at successive 15-bit offsets —
    /// the EF stays selected across calls.
    pub async fn write_file_unauthenticated<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u16,
        data: &[u8],
    ) -> Result<(), SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        if self.ef_selected != Some(file.file_id()) {
            iso_select_ef_by_fid(transport, file.file_id()).await?;
            self.ef_selected = Some(file.file_id());
        }

        if data.is_empty() {
            // Surface the empty-data error from `iso_update_binary`.
            return iso_update_binary(transport, None, offset, data).await;
        }

        let mut written: usize = 0;
        while written < data.len() {
            let chunk_len = (data.len() - written).min(ISO_UPDATE_BINARY_CHUNK);
            let abs = offset as usize + written;
            if abs > 0x7FFF {
                return Err(SessionError::InvalidCommandParameter {
                    parameter: "offset",
                    value: abs,
                    reason: "must be <= 0x7FFF",
                });
            }
            iso_update_binary(
                transport,
                None,
                abs as u16,
                &data[written..written + chunk_len],
            )
            .await?;
            written += chunk_len;
        }
        Ok(())
    }

    /// Retrieve a file's settings.
    pub async fn get_file_settings<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
    ) -> Result<FileSettingsView, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        get_file_settings(transport, file.file_no()).await
    }

    /// Read software, hardware and production version information.
    ///
    /// Uses plain mode communication. For authenticated sessions
    /// there is also a [MAC mode variant available](`Session::<Authenticated<_>>::get_version`).
    ///
    /// Borrows `self` rather than consuming it — there is no secure channel
    /// state to desynchronise on an unauthenticated session, so a failed call
    /// can be retried without re-creating the session.
    pub async fn get_version<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Version, SessionError<T::Error>> {
        get_version(transport).await
    }

    /// Perform AES authentication.
    ///
    /// The caller must provide the 16-byte key and the PCD challenge `rnd_a`
    /// (the caller owns entropy).
    pub async fn authenticate_aes<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<AesSuite>>, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        let ef_selected = self.ef_selected;
        let auth_result = authenticate_ev2_first_aes(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::with_auth_result(auth_result, key_no),
            ndef_selected: true,
            ef_selected,
        })
    }

    /// Perform LRP authentication.
    ///
    /// The tag must have been put into LRP
    /// mode beforehand via [`Session::enable_lrp`].
    ///
    /// The caller must provide the key and the PCD challenge `rnd_a`
    /// (the caller owns entropy).
    pub async fn authenticate_lrp<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<LrpSuite>>, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        let ef_selected = self.ef_selected;
        let auth_result = authenticate_ev2_first_lrp(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::with_auth_result(auth_result, key_no),
            ndef_selected: true,
            ef_selected,
        })
    }

    /// Verify tag originality by its UID.
    ///
    /// Reads the 56-byte ECDSA originality signature from the
    /// PICC and verifies it using the NXP master public key.
    /// On success the verified [`crate::OriginalitySignature`] is returned so the
    /// caller can inspect or store the raw signature bytes.
    ///
    /// The provided UID must not be a randomized ID - use [`AuthenticatedSession::get_uid`] if needed.
    ///
    /// Requires the `originality` feature (default-on).
    #[cfg(feature = "originality")]
    pub async fn verify_originality<T: Transport>(
        &self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<originality::OriginalitySignature, SessionError<T::Error>> {
        let sig = read_sig(transport).await?;
        let sig = originality::OriginalitySignature::from_bytes(sig);
        sig.verify(uid)
            .map_err(SessionError::OriginalityVerificationFailed)?;
        Ok(sig)
    }

    /// Check if the tag is in factory state.
    ///
    /// The tag is considered in factory state iff.
    ///
    /// - the version information matches the factory state version,
    /// - the originality signature is valid for the factory state UID,
    /// - the keys are still set to their default values,
    /// - the capability container has the default value,
    /// - the NDEF file and proprietary file are empty and have default settings.
    ///
    /// Additionally it reports on the following:
    ///
    /// - Whether random ID mode is active (can not be reversed, but might be acceptable),
    /// - whether LRP mode is active (can not be reversed, but might be acceptable),
    /// - whether the tag has tag-tamper mode enabled (can not be reversed, but might be
    ///   acceptable), and
    /// - the originality signature and UID of the tag.
    ///
    /// Requires the `originality` feature (default-on) — the factory-state
    /// criteria include NXP originality-signature verification.
    #[cfg(feature = "originality")]
    pub async fn check_factory_state<T: Transport>(
        &mut self,
        transport: &mut T,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<FactoryStateCheckResult, SessionError<T::Error>> {
        use rand::RngExt as _;

        let mut buf = [0u8; 256];
        let cc_size = File::CapabilityContainer.size() as usize;
        self.read_file_unauthenticated(
            transport,
            File::CapabilityContainer,
            0,
            &mut buf[..cc_size],
        )
        .await
        .map_err(|_| SessionError::NotFactoryState("unable to read capability container"))?;
        if CapabilityContainer::from_bytes(&buf[..cc_size]) != Ok(CapabilityContainer::default()) {
            return Err(SessionError::NotFactoryState(
                "capability container mismatch",
            ));
        }

        let version = self.get_version(transport).await?;
        if !version.is_ntag_424() {
            return Err(SessionError::NotFactoryState("version mismatch"));
        }

        // Check NDEF content
        let ndef = &mut buf[..File::Ndef.size() as usize];
        self.read_file_unauthenticated(transport, File::Ndef, 0, ndef)
            .await
            .map_err(|_| SessionError::NotFactoryState("unable to read NDEF file"))?;
        if ndef.iter().any(|&b| b != 0) {
            return Err(SessionError::NotFactoryState("NDEF file not empty"));
        }

        // Check master key
        let mut master_session: EncryptedSession = match Session::new()
            .authenticate_aes(transport, KeyNumber::Key0, &[0u8; 16], rng.random())
            .await
        {
            Ok(s) => s.into(),
            Err(_) => Session::new()
                .authenticate_lrp(transport, KeyNumber::Key0, &[0u8; 16], rng.random())
                .await
                .map_err(|_| {
                    SessionError::NotFactoryState("unable to authenticate with default keys")
                })?
                .into(),
        };

        // Check file settings
        for file in [File::CapabilityContainer, File::Ndef, File::Proprietary] {
            let (view, session) = master_session
                .get_file_settings(transport, file)
                .await
                .map_err(|_| SessionError::NotFactoryState("unable to read file settings"))?;
            if view != FileSettingsView::factory(file) {
                return Err(SessionError::NotFactoryState("file settings mismatch"));
            }
            master_session = session;
        }

        let mode = master_session.mode();
        let tag_tamper_status = if version.has_tag_tamper_support() {
            let (status, s) = master_session
                .get_tt_status(transport)
                .await
                .map_err(|_| SessionError::NotFactoryState("unable to read tag-tamper status"))?;
            master_session = s;
            Some(status)
        } else {
            None
        };

        // Check UID and originality signature
        let (uid, master_session) = master_session
            .get_uid(transport)
            .await
            .map_err(|_| SessionError::NotFactoryState("unable to read UID with default keys"))?;
        let (master_session, signature) = master_session
            .verify_originality(transport, &uid)
            .await
            .map_err(|_| {
                SessionError::NotFactoryState(
                    "originality signature verification failed with default keys",
                )
            })?;

        let key2 = master_session
            .authenticate(transport, KeyNumber::Key2, &[0u8; 16], rng.random())
            .await
            .map_err(|_| {
                SessionError::NotFactoryState("unable to authenticate with default key 2")
            })?;

        // Check proprietary file content (requires key 2 for reading).
        // NXP programs a 2-byte big-endian capacity header [0x00, 0x7E] (= 126 =
        // file size − 2) into the proprietary file at manufacture; the remaining
        // 126 bytes are zero. This is not documented in the public datasheet but
        // is consistent across hardware and follows the same length-prefix
        // convention as CCLEN and NLEN in the other files.
        const FACTORY_PROP: [u8; 128] = {
            let mut b = [0u8; 128];
            b[1] = 0x7E;
            b
        };
        let prop = &mut buf[..File::Proprietary.size() as usize];
        let (_, key2) = key2
            .read_file_with_mode(transport, File::Proprietary, 0, 128, CommMode::Full, prop)
            .await
            .map_err(|_| SessionError::NotFactoryState("unable to read proprietary file"))?;
        if prop != FACTORY_PROP {
            return Err(SessionError::NotFactoryState("proprietary file not empty"));
        }

        // Check default keys 1, 3, 4
        let mut session = key2;
        for key in [KeyNumber::Key1, KeyNumber::Key3, KeyNumber::Key4] {
            let s = session
                .authenticate(transport, key, &[0u8; 16], rng.random())
                .await
                .map_err(|_| {
                    SessionError::NotFactoryState("unable to authenticate with default keys")
                })?;
            session = s;
        }

        let random_id_mode = version.uid()[0] == 0x08;
        Ok(FactoryStateCheckResult {
            random_id_mode,
            mode,
            tag_tamper_status,
            originality_signature: signature,
            uid,
        })
    }
}

/// Result of [`Session::check_factory_state`].
///
/// Returned when the tag passes all mandatory factory-state checks: default
/// keys, default file settings, empty NDEF and proprietary files, valid
/// originality signature, and a matching version fingerprint.
///
/// Some irreversible configuration changes — random-ID mode, LRP mode, and
/// tag-tamper arming — are allowed to have been applied before delivery.
/// The fields below report their state so the caller can decide whether those
/// conditions are acceptable for its use case. Use [`strictly`](`Self::strictly`)
/// if all three must still be at their factory defaults.
///
/// Only available with the `originality` feature (default-on).
#[cfg(feature = "originality")]
pub struct FactoryStateCheckResult {
    /// Whether random ID mode is active.
    ///
    /// This can not be reversed, but might be acceptable depending on the use case.
    pub random_id_mode: bool,
    /// The tag's crypto mode.
    pub mode: CryptoMode,
    /// The tag's tag-tamper status if supported by the version.
    ///
    /// This can not be reversed, but might be acceptable depending on the use case.
    pub tag_tamper_status: Option<TagTamperStatusReadout>,
    /// The originality signature verified under the default keys.
    pub originality_signature: originality::OriginalitySignature,
    /// The UID of the tag.
    pub uid: [u8; 7],
}

#[cfg(feature = "originality")]
impl FactoryStateCheckResult {
    /// Returns `true` if no irreversible changes have been applied since manufacture.
    ///
    /// Requires: random-ID mode off, AES crypto mode (not LRP), and — on
    /// tag-tamper-capable hardware — both the permanent and current tamper
    /// status are [`TagTamperStatus::Invalid`] (i.e. tag-tamper detection has
    /// never been armed).
    pub fn strictly(&self) -> bool {
        !self.random_id_mode
            && matches!(self.mode, CryptoMode::Aes)
            && match self.tag_tamper_status {
                None => true,
                Some(s) => {
                    matches!(s.permanent(), TagTamperStatus::Invalid)
                        && matches!(s.current(), TagTamperStatus::Invalid)
                }
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Exchange, TestTransport, block_on};
    use alloc::vec;

    /// `D27600008501010000` — NDEF application DF name (§10.9.1).
    const SELECT_NDEF_APP: [u8; 13] = [
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
    ];

    /// `00 A4 00 0C 02 E1 04` — select NDEF EF (`E1 04`), no FCI.
    const SELECT_NDEF_EF: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04];

    /// 256-byte write splits into a 255-byte and a 1-byte
    /// `ISOUpdateBinary` at offset 0 and offset 255 — `Lc` is one byte so
    /// a single APDU caps at 255.
    #[test]
    fn write_file_unauthenticated_chunks_at_255_byte_boundary() {
        let payload = &crate::testing::TEST_PAYLOAD_256;

        // Chunk 1: 00 D6 00 00 FF <data[0..255]>
        let mut apdu1 = vec![0x00, 0xD6, 0x00, 0x00, 0xFF];
        apdu1.extend_from_slice(&payload[..255]);
        // Chunk 2: 00 D6 00 FF 01 <data[255]>  (offset = 0x00FF)
        let apdu2 = [0x00, 0xD6, 0x00, 0xFF, 0x01, payload[255]];

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&SELECT_NDEF_EF, &[], 0x90, 0x00),
            Exchange::new(&apdu1, &[], 0x90, 0x00),
            Exchange::new(&apdu2, &[], 0x90, 0x00),
        ]);

        block_on(Session::new().write_file_unauthenticated(&mut transport, File::Ndef, 0, payload))
            .expect("chunked write ok");
        assert_eq!(transport.remaining(), 0);
    }

    /// 512-byte read split into two 256-byte `ISOReadBinary` APDUs.
    #[test]
    fn read_file_unauthenticated_chunks_at_256_byte_boundary() {
        let mut payload1 = [0u8; 256];
        let mut payload2 = [0u8; 256];
        for (i, b) in payload1.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in payload2.iter_mut().enumerate() {
            *b = (i ^ 0xAA) as u8;
        }

        // Chunk 1: 00 B0 00 00 00 (Le=00 → 256 bytes), offset 0.
        let apdu1 = [0x00, 0xB0, 0x00, 0x00, 0x00];
        // Chunk 2: 00 B0 01 00 00, offset 0x0100 = 256.
        let apdu2 = [0x00, 0xB0, 0x01, 0x00, 0x00];

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&SELECT_NDEF_EF, &[], 0x90, 0x00),
            Exchange::new(&apdu1, &payload1, 0x90, 0x00),
            Exchange::new(&apdu2, &payload2, 0x90, 0x00),
        ]);

        let mut buf = [0u8; 512];
        let n = block_on(Session::new().read_file_unauthenticated(
            &mut transport,
            File::Ndef,
            0,
            &mut buf,
        ))
        .expect("chunked read ok");
        assert_eq!(n, 512);
        assert_eq!(&buf[..256], &payload1);
        assert_eq!(&buf[256..], &payload2);
        assert_eq!(transport.remaining(), 0);
    }

    /// A short payload from the PICC ends the read early — no further
    /// APDUs are issued past the file boundary.
    #[test]
    fn read_file_unauthenticated_stops_on_short_payload() {
        let payload = [0xABu8; 100];
        // Buffer is 256 bytes; PICC returns only 100 → file boundary.
        let apdu = [0x00, 0xB0, 0x00, 0x00, 0x00];

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&SELECT_NDEF_EF, &[], 0x90, 0x00),
            Exchange::new(&apdu, &payload, 0x90, 0x00),
        ]);

        let mut buf = [0u8; 256];
        let n = block_on(Session::new().read_file_unauthenticated(
            &mut transport,
            File::Ndef,
            0,
            &mut buf,
        ))
        .expect("read ok");
        assert_eq!(n, 100);
        assert_eq!(&buf[..100], &payload);
        assert_eq!(transport.remaining(), 0);
    }
}
