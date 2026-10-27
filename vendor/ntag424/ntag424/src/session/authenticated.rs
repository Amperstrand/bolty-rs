// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::*;
use crate::{Access, FileSettingsUpdate, commands::AuthResult, types::file_settings::CryptoMode};

/// State of an authenticated session.
///
/// The session suite `S` determines the cryptographic algorithms, the tag
/// supports AES and LRP.
pub struct Authenticated<S: SessionSuite> {
    auth_result: AuthResult<S>,
    key_number: KeyNumber,
    cmd_counter: u16,
}

impl<S: SessionSuite> Authenticated<S> {
    #[cfg(test)]
    pub(crate) fn new(suite: S, ti: [u8; 4], key_number: KeyNumber) -> Self {
        Self::with_auth_result(
            AuthResult {
                suite,
                ti,
                pd_cap2: [0; 6],
                pcd_cap2: [0; 6],
            },
            key_number,
        )
    }

    pub(crate) fn with_auth_result(auth_result: AuthResult<S>, key_number: KeyNumber) -> Self {
        Self {
            auth_result,
            key_number,
            cmd_counter: 0,
        }
    }

    /// Construct a re-authenticated state.
    ///
    /// Preserves `ti` and `cmd_counter` from the prior session while
    /// replacing the suite with newly derived keys. Used by NonFirst
    /// auth (§9.1.6, §9.2.6).
    #[cfg(test)]
    pub(crate) fn non_first(
        suite: S,
        ti: [u8; 4],
        cmd_counter: u16,
        key_number: KeyNumber,
    ) -> Self {
        Self::non_first_with_auth_result(
            AuthResult {
                suite,
                ti,
                pd_cap2: [0; 6],
                pcd_cap2: [0; 6],
            },
            cmd_counter,
            key_number,
        )
    }

    pub(crate) fn non_first_with_auth_result(
        auth_result: AuthResult<S>,
        cmd_counter: u16,
        key_number: KeyNumber,
    ) -> Self {
        Self {
            auth_result,
            key_number,
            cmd_counter,
        }
    }

    pub(crate) fn suite(&self) -> &S {
        &self.auth_result.suite
    }

    pub(crate) fn suite_mut(&mut self) -> &mut S {
        &mut self.auth_result.suite
    }

    pub(crate) fn ti_bytes(&self) -> &[u8; 4] {
        &self.auth_result.ti
    }

    pub(crate) fn counter(&self) -> u16 {
        self.cmd_counter
    }

    /// Advance `CmdCtr` by one (§9.1.2). Called after a successful
    /// secure-messaging exchange (MAC or FULL); `CmdCtr` stays put on
    /// failure and on `CommMode.Plain` passthrough.
    pub(crate) fn advance_counter(&mut self) {
        self.cmd_counter = self.cmd_counter.wrapping_add(1);
    }
}

/// Max plaintext bytes per single `CommMode.Plain` `ReadData` APDU.
///
/// Short-`Le` cap is 256 bytes (§8.4 Table 16); plain-mode responses
/// have no MAC overhead, so the full 256 bytes are user data.
const PLAIN_READ_CHUNK: u32 = 256;

/// Max plaintext bytes per single `CommMode.Plain` `WriteData` APDU.
///
/// Body = `header(7) || data ≤ 255` ⇒ data ≤ 248 bytes per APDU.
const PLAIN_WRITE_CHUNK: usize = 248;

/// Plain-mode chunked `ReadData` driver.
///
/// `read_data_plain` is the only command in the read/write set that
/// doesn't take a `SecureChannel`, so it can't advance `CmdCtr` itself.
/// The chunk loop therefore lives here in the session layer where the
/// `Authenticated<S>` state is in scope - one `advance_counter` call
/// per APDU keeps the library's `CmdCtr` in sync with the PICC's.
///
/// `length == 0` means "rest of file" and is sent as a single APDU
/// (the PICC caps the response at the short-`Le` limit).
pub(crate) async fn read_file_plain_chunked<T: Transport, S: SessionSuite>(
    state: &mut Authenticated<S>,
    transport: &mut T,
    file_no: u8,
    offset: u32,
    length: u32,
    buf: &mut [u8],
) -> Result<usize, SessionError<T::Error>> {
    if length == 0 {
        let n = read_data_plain(transport, file_no, offset, length, buf).await?;
        state.advance_counter();
        return Ok(n);
    }

    let mut total: usize = 0;
    let mut current_offset = offset;
    let mut remaining = length;
    while remaining > 0 {
        let chunk = remaining.min(PLAIN_READ_CHUNK);
        let chunk_usize = chunk as usize;
        let n = read_data_plain(
            transport,
            file_no,
            current_offset,
            chunk,
            &mut buf[total..total + chunk_usize],
        )
        .await?;
        state.advance_counter();
        total += n;
        if n < chunk_usize {
            // Short response from the PICC; treat as EOF and stop.
            break;
        }
        current_offset = current_offset.wrapping_add(chunk);
        remaining -= chunk;
    }
    Ok(total)
}

/// Plain-mode chunked `WriteData` driver. See [`read_file_plain_chunked`]
/// for why the loop lives here rather than in [`write_data_plain`].
pub(crate) async fn write_file_plain_chunked<T: Transport, S: SessionSuite>(
    state: &mut Authenticated<S>,
    transport: &mut T,
    file_no: u8,
    offset: u32,
    data: &[u8],
) -> Result<(), SessionError<T::Error>> {
    if data.is_empty() {
        // Mirror `write_data_plain`'s validation so empty writes still
        // surface as an error in the chunked path (the loop below would
        // otherwise just return `Ok(())`).
        return Err(SessionError::InvalidCommandParameter {
            parameter: "data.len()",
            value: 0,
            reason: "must be non-zero",
        });
    }

    let mut written: usize = 0;
    let mut current_offset = offset;
    while written < data.len() {
        let end = (written + PLAIN_WRITE_CHUNK).min(data.len());
        write_data_plain(transport, file_no, current_offset, &data[written..end]).await?;
        state.advance_counter();
        current_offset = current_offset.wrapping_add((end - written) as u32);
        written = end;
    }
    Ok(())
}

macro_rules! impl_authenticated_session {
    ($suite:ty, $authenticate:item) => {
        impl AuthenticatedSession for Session<Authenticated<$suite>> {
            $authenticate

            fn mode(&self) -> CryptoMode {
                <$suite>::MODE
            }

            fn key_number(&self) -> KeyNumber {
                self.state.key_number
            }

            async fn get_version<T: Transport>(
                mut self,
                transport: &mut T,
            ) -> Result<(Version, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let version = get_version_mac(transport, &mut channel).await?;
                Ok((version, self))
            }

            async fn change_key<T: Transport>(
                mut self,
                transport: &mut T,
                key_no: NonMasterKeyNumber,
                new_key: &[u8; 16],
                new_key_version: u8,
                old_key: &[u8; 16],
            ) -> Result<Self, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                change_key(
                    transport,
                    &mut channel,
                    key_no,
                    new_key,
                    new_key_version,
                    old_key,
                )
                .await?;
                Ok(self)
            }

            async fn change_master_key<T: Transport>(
                mut self,
                transport: &mut T,
                new_key: &[u8; 16],
                new_key_version: u8,
            ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                change_master_key(transport, &mut channel, new_key, new_key_version).await?;
                Ok(Session::new())
            }

            async fn get_uid<T: Transport>(
                mut self,
                transport: &mut T,
            ) -> Result<([u8; 7], Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let uid = get_card_uid(transport, &mut channel).await?;
                Ok((uid, self))
            }

            async fn get_key_version<T: Transport>(
                mut self,
                transport: &mut T,
                key_no: KeyNumber,
            ) -> Result<(u8, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let version = get_key_version(transport, &mut channel, key_no).await?;
                Ok((version, self))
            }

            async fn get_file_settings<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
            ) -> Result<(FileSettingsView, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let settings =
                    get_file_settings_mac(transport, &mut channel, file.file_no()).await?;
                Ok((settings, self))
            }

            async fn get_file_counters<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
            ) -> Result<(u32, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let counter = get_file_counters(transport, &mut channel, file.file_no()).await?;
                Ok((counter, self))
            }

            async fn get_tt_status<T: Transport>(
                mut self,
                transport: &mut T,
            ) -> Result<(TagTamperStatusReadout, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let status = get_tt_status(transport, &mut channel).await?;
                Ok((status, self))
            }

            async fn set_configuration<T: Transport>(
                mut self,
                transport: &mut T,
                configuration: &Configuration,
            ) -> Result<Self, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                set_configuration(transport, &mut channel, configuration).await?;
                Ok(self)
            }

            async fn change_file_settings<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
                settings: &FileSettingsUpdate,
            ) -> Result<Self, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                change_file_settings(transport, &mut channel, file.file_no(), settings).await?;
                Ok(self)
            }

            #[cfg(feature = "originality")]
            async fn verify_originality<T: Transport>(
                mut self,
                transport: &mut T,
                uid: &[u8; 7],
            ) -> Result<(Self, originality::OriginalitySignature), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let sig = read_sig_mac(transport, &mut channel).await?;
                let sig = originality::OriginalitySignature::from_bytes(sig);
                sig.verify(uid)
                    .map_err(SessionError::OriginalityVerificationFailed)?;
                Ok((self, sig))
            }

            async fn read_file_plain<T: Transport>(
                &mut self,
                transport: &mut T,
                file: File,
                offset: u32,
                length: u32,
                buf: &mut [u8],
            ) -> Result<usize, SessionError<T::Error>> {
                read_file_plain_chunked(
                    &mut self.state,
                    transport,
                    file.file_no(),
                    offset,
                    length,
                    buf,
                )
                .await
            }

            async fn read_file_with_mode<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
                offset: u32,
                length: u32,
                mode: CommMode,
                buf: &mut [u8],
            ) -> Result<(usize, Self), SessionError<T::Error>> {
                match mode {
                    CommMode::Plain => {
                        let n = read_file_plain_chunked(
                            &mut self.state,
                            transport,
                            file.file_no(),
                            offset,
                            length,
                            buf,
                        )
                        .await?;
                        Ok((n, self))
                    }
                    CommMode::Mac => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        let n = read_data_mac(
                            transport,
                            &mut channel,
                            file.file_no(),
                            offset,
                            length,
                            buf,
                        )
                        .await?;
                        Ok((n, self))
                    }
                    CommMode::Full => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        let n = read_data_full(
                            transport,
                            &mut channel,
                            file.file_no(),
                            offset,
                            length,
                            buf,
                        )
                        .await?;
                        Ok((n, self))
                    }
                }
            }

            async fn write_file_plain<T: Transport>(
                &mut self,
                transport: &mut T,
                file: File,
                offset: u32,
                data: &[u8],
            ) -> Result<(), SessionError<T::Error>> {
                write_file_plain_chunked(
                    &mut self.state,
                    transport,
                    file.file_no(),
                    offset,
                    data,
                )
                .await
            }

            async fn write_file_with_mode<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
                offset: u32,
                data: &[u8],
                mode: CommMode,
            ) -> Result<Self, SessionError<T::Error>> {
                match mode {
                    CommMode::Plain => {
                        write_file_plain_chunked(
                            &mut self.state,
                            transport,
                            file.file_no(),
                            offset,
                            data,
                        )
                        .await?;
                        Ok(self)
                    }
                    CommMode::Mac => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        write_data_mac(transport, &mut channel, file.file_no(), offset, data)
                            .await?;
                        Ok(self)
                    }
                    CommMode::Full => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        write_data_full(transport, &mut channel, file.file_no(), offset, data)
                            .await?;
                        Ok(self)
                    }
                }
            }

            async fn write_file<T: Transport>(
                self,
                transport: &mut T,
                file: File,
                offset: u32,
                data: &[u8],
            ) -> Result<Self, SessionError<T::Error>> {
                let (settings, session) = self.get_file_settings(transport, file).await?;
                let rights = &settings.access_rights;
                let free_access = rights.write == Access::Free || rights.read_write == Access::Free;
                let my_key = Access::Key(session.key_number());
                let me_write = rights.write == my_key || rights.read_write == my_key;
                // 8.2.3.3
                let comm_mode = if free_access && !me_write {
                    CommMode::Plain
                } else {
                    settings.comm_mode
                };
                session
                    .write_file_with_mode(transport, file, offset, data, comm_mode)
                    .await
            }

            async fn read_file<T: Transport>(
                self,
                transport: &mut T,
                file: File,
                offset: u32,
                length: u32,
                buf: &mut [u8],
            ) -> Result<(usize, Self), SessionError<T::Error>> {
                let (settings, session) = self.get_file_settings(transport, file).await?;
                let rights = &settings.access_rights;
                let free_access = rights.read == Access::Free || rights.read_write == Access::Free;
                let my_key = Access::Key(session.key_number());
                let me_read = rights.read == my_key || rights.read_write == my_key;
                // 8.2.3.3
                let comm_mode = if free_access && !me_read {
                    CommMode::Plain
                } else {
                    settings.comm_mode
                };
                session
                    .read_file_with_mode(transport, file, offset, length, comm_mode, buf)
                    .await
            }

            fn ti(&self) -> &[u8; 4] {
                &self.state.auth_result.ti
            }

            fn pd_cap2(&self) -> &[u8; 6] {
                &self.state.auth_result.pd_cap2
            }

            fn pcd_cap2(&self) -> &[u8; 6] {
                &self.state.auth_result.pcd_cap2
            }

            fn cmd_counter(&self) -> u16 {
                self.state.cmd_counter
            }
        }
    };
}

impl_authenticated_session!(
    AesSuite,
    async fn authenticate<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let cmd_counter = self.state.counter();
        let suite = authenticate_ev2_non_first_aes(transport, key_no, key, rnd_a).await?;
        let auth_result = AuthResult {
            suite,
            ..self.state.auth_result
        };
        self.state = Authenticated::non_first_with_auth_result(auth_result, cmd_counter, key_no);
        Ok(self)
    }
);
impl_authenticated_session!(
    LrpSuite,
    async fn authenticate<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let cmd_counter = self.state.counter();
        let suite = authenticate_ev2_non_first_lrp(transport, key_no, key, rnd_a).await?;
        let auth_result = AuthResult {
            suite,
            ..self.state.auth_result
        };
        self.state = Authenticated::non_first_with_auth_result(auth_result, cmd_counter, key_no);
        Ok(self)
    }
);

impl Session<Authenticated<AesSuite>> {
    /// Enable LRP mode on the tag.
    ///
    /// <div class="warning">The switch is permanent (NT4H2421Gx §8).</div>
    ///
    /// Consumes the authenticated AES session: enabling LRP tears down the
    /// secure channel on the PICC. The next authentication must be
    /// [`Session::authenticate_lrp`].
    ///
    /// LRP is an AES-based cipher that is more resistant against side-channel
    /// attacks but is not supported by all NFC readers. Unauthenticated reads
    /// are _not_ affected by this switch.
    ///
    /// The type system prevents calling this method twice: after enabling LRP
    /// you can only authenticate with [`Session::authenticate_lrp`], which
    /// returns a `Session<Authenticated<LrpSuite>>` that has no `enable_lrp`
    /// method. At the PICC level, sending `SetConfiguration` with LRP already
    /// active is a no-op (NT4H2421Gx §8), so error-recovery code that
    /// unconditionally issues the command is safe.
    pub async fn enable_lrp<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
        let configuration = Configuration::new().with_lrp_enabled();
        {
            let mut channel = SecureChannel::new(&mut self.state);
            set_configuration(transport, &mut channel, &configuration).await?;
        }
        Ok(Session {
            state: Unauthenticated,
            ndef_selected: self.ndef_selected,
            ef_selected: self.ef_selected,
        })
    }
}

impl From<Session<Authenticated<AesSuite>>> for EncryptedSession {
    fn from(val: Session<Authenticated<AesSuite>>) -> Self {
        EncryptedSession::Aes(val)
    }
}

impl From<Session<Authenticated<LrpSuite>>> for EncryptedSession {
    fn from(val: Session<Authenticated<LrpSuite>>) -> Self {
        EncryptedSession::Lrp(val)
    }
}

#[allow(clippy::large_enum_variant)]
/// A session in an authenticated state, with the session suite erased.
///
/// Use this when code should operate on an authenticated session without
/// committing to AES or LRP at the type level.
///
/// `EncryptedSession` preserves the same consuming semantics as
/// [`AuthenticatedSession`]: commands dispatch to the underlying
/// `Session<Authenticated<AesSuite>>` or `Session<Authenticated<LrpSuite>>`
/// and return a new `EncryptedSession` on success.
pub enum EncryptedSession {
    Aes(Session<Authenticated<AesSuite>>),
    Lrp(Session<Authenticated<LrpSuite>>),
}

impl AuthenticatedSession for EncryptedSession {
    fn mode(&self) -> CryptoMode {
        match self {
            EncryptedSession::Aes(session) => session.mode(),
            EncryptedSession::Lrp(session) => session.mode(),
        }
    }

    fn key_number(&self) -> KeyNumber {
        match self {
            EncryptedSession::Aes(session) => session.state.key_number,
            EncryptedSession::Lrp(session) => session.state.key_number,
        }
    }

    async fn get_version<T: Transport>(
        self,
        transport: &mut T,
    ) -> Result<(Version, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (version, session) = session.get_version(transport).await?;
                Ok((version, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (version, session) = session.get_version(transport).await?;
                Ok((version, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn change_key<T: Transport>(
        self,
        transport: &mut T,
        key_no: NonMasterKeyNumber,
        new_key: &[u8; 16],
        new_key_version: u8,
        old_key: &[u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .change_key(transport, key_no, new_key, new_key_version, old_key)
                    .await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .change_key(transport, key_no, new_key, new_key_version, old_key)
                    .await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn change_master_key<T: Transport>(
        self,
        transport: &mut T,
        new_key: &[u8; 16],
        new_key_version: u8,
    ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .change_master_key(transport, new_key, new_key_version)
                    .await?;
                Ok(session)
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .change_master_key(transport, new_key, new_key_version)
                    .await?;
                Ok(session)
            }
        }
    }

    async fn get_uid<T: Transport>(
        self,
        transport: &mut T,
    ) -> Result<([u8; 7], Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (uid, session) = session.get_uid(transport).await?;
                Ok((uid, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (uid, session) = session.get_uid(transport).await?;
                Ok((uid, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_key_version<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
    ) -> Result<(u8, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (version, session) = session.get_key_version(transport, key_no).await?;
                Ok((version, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (version, session) = session.get_key_version(transport, key_no).await?;
                Ok((version, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_file_settings<T: Transport>(
        self,
        transport: &mut T,
        file: File,
    ) -> Result<(FileSettingsView, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (settings, session) = session.get_file_settings(transport, file).await?;
                Ok((settings, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (settings, session) = session.get_file_settings(transport, file).await?;
                Ok((settings, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_file_counters<T: Transport>(
        self,
        transport: &mut T,
        file: File,
    ) -> Result<(u32, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (counter, session) = session.get_file_counters(transport, file).await?;
                Ok((counter, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (counter, session) = session.get_file_counters(transport, file).await?;
                Ok((counter, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_tt_status<T: Transport>(
        self,
        transport: &mut T,
    ) -> Result<(TagTamperStatusReadout, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (status, session) = session.get_tt_status(transport).await?;
                Ok((status, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (status, session) = session.get_tt_status(transport).await?;
                Ok((status, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn set_configuration<T: Transport>(
        self,
        transport: &mut T,
        configuration: &Configuration,
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.set_configuration(transport, configuration).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.set_configuration(transport, configuration).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn change_file_settings<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        settings: &FileSettingsUpdate,
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .change_file_settings(transport, file, settings)
                    .await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .change_file_settings(transport, file, settings)
                    .await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    #[cfg(feature = "originality")]
    async fn verify_originality<T: Transport>(
        self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<(Self, originality::OriginalitySignature), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (session, sig) = session.verify_originality(transport, uid).await?;
                Ok((EncryptedSession::Aes(session), sig))
            }
            EncryptedSession::Lrp(session) => {
                let (session, sig) = session.verify_originality(transport, uid).await?;
                Ok((EncryptedSession::Lrp(session), sig))
            }
        }
    }

    async fn read_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> Result<usize, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let n = session
                    .read_file_plain(transport, file, offset, length, buf)
                    .await?;
                Ok(n)
            }
            EncryptedSession::Lrp(session) => {
                let n = session
                    .read_file_plain(transport, file, offset, length, buf)
                    .await?;
                Ok(n)
            }
        }
    }

    async fn read_file_with_mode<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        mode: CommMode,
        buf: &mut [u8],
    ) -> Result<(usize, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (n, session) = session
                    .read_file_with_mode(transport, file, offset, length, mode, buf)
                    .await?;
                Ok((n, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (n, session) = session
                    .read_file_with_mode(transport, file, offset, length, mode, buf)
                    .await?;
                Ok((n, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn write_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> Result<(), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                session
                    .write_file_plain(transport, file, offset, data)
                    .await?;
                Ok(())
            }
            EncryptedSession::Lrp(session) => {
                session
                    .write_file_plain(transport, file, offset, data)
                    .await?;
                Ok(())
            }
        }
    }

    async fn write_file_with_mode<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
        mode: CommMode,
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .write_file_with_mode(transport, file, offset, data, mode)
                    .await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .write_file_with_mode(transport, file, offset, data, mode)
                    .await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn write_file<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.write_file(transport, file, offset, data).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.write_file(transport, file, offset, data).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn read_file<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> Result<(usize, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (n, session) = session
                    .read_file(transport, file, offset, length, buf)
                    .await?;
                Ok((n, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (n, session) = session
                    .read_file(transport, file, offset, length, buf)
                    .await?;
                Ok((n, EncryptedSession::Lrp(session)))
            }
        }
    }

    fn ti(&self) -> &[u8; 4] {
        match self {
            EncryptedSession::Aes(session) => session.ti(),
            EncryptedSession::Lrp(session) => session.ti(),
        }
    }

    fn pd_cap2(&self) -> &[u8; 6] {
        match self {
            EncryptedSession::Aes(session) => session.pd_cap2(),
            EncryptedSession::Lrp(session) => session.pd_cap2(),
        }
    }

    fn pcd_cap2(&self) -> &[u8; 6] {
        match self {
            EncryptedSession::Aes(session) => session.pcd_cap2(),
            EncryptedSession::Lrp(session) => session.pcd_cap2(),
        }
    }

    fn cmd_counter(&self) -> u16 {
        match self {
            EncryptedSession::Aes(session) => session.cmd_counter(),
            EncryptedSession::Lrp(session) => session.cmd_counter(),
        }
    }

    async fn authenticate<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.authenticate(transport, key_no, key, rnd_a).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.authenticate(transport, key_no, key, rnd_a).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
    use alloc::vec;

    /// `D27600008501010000` — NDEF application DF name (§10.9.1).
    const SELECT_NDEF_APP: [u8; 13] = [
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
    ];

    /// Hardware-pinned: 256-byte CommMode.Plain `WriteData` to the NDEF
    /// file (`FileNo=02`, AES Key0 session) splits at the 248-byte
    /// plaintext boundary.
    ///
    /// The trace was captured against an NDEF file whose access rights
    /// permit free writes (`GetFileSettings` returns `CommMode = 00h`),
    /// so the high-level `write_file` dispatches to `write_data_plain`
    /// via the session-layer chunker. The two `WriteData` APDUs are sent
    /// without MAC/encryption — the auth handshake exists only to reach
    /// the session that retrieves file settings.
    #[test]
    fn write_file_plain_chunked_aes_hardware_capture() {
        let payload = &crate::testing::TEST_PAYLOAD_256;
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("040313D1647757509A5F3C4569EA913C");

        let auth_part1_send = hex_bytes("9071000005000300000000");
        let auth_part1_resp = hex_bytes("7CB5AD158827AF5DE233EE71DC818E85");
        let auth_part2_send = hex_bytes(
            "90AF000020B83C7073C1534C2DDE8332DE5C7B026D7D8B581282F46DDFDC04AD7886747107\
             00",
        );
        let auth_part2_resp =
            hex_bytes("B052367408D89B6A90C2236AB3DE952CD688A29E06D659F3FC651884ED688C91");

        let get_file_settings_send = hex_bytes("90F50000090285E97C38B1770C3500");
        let get_file_settings_resp = hex_bytes("0000E0EE0001007CAB66A4CE70ABAD");

        // Chunk 1: 90 8D 00 00 FF | 02 00 00 00 F8 00 00 | data[0..248] | 00
        let mut chunk1_send = vec![0x90, 0x8D, 0x00, 0x00, 0xFF];
        chunk1_send.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00]);
        chunk1_send.extend_from_slice(&payload[..248]);
        chunk1_send.push(0x00);

        // Chunk 2: 90 8D 00 00 0F | 02 F8 00 00 08 00 00 | data[248..256] | 00
        let mut chunk2_send = vec![0x90, 0x8D, 0x00, 0x00, 0x0F];
        chunk2_send.extend_from_slice(&[0x02, 0xF8, 0x00, 0x00, 0x08, 0x00, 0x00]);
        chunk2_send.extend_from_slice(&payload[248..]);
        chunk2_send.push(0x00);

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&auth_part1_send, &auth_part1_resp, 0x91, 0xAF),
            Exchange::new(&auth_part2_send, &auth_part2_resp, 0x91, 0x00),
            Exchange::new(&get_file_settings_send, &get_file_settings_resp, 0x91, 0x00),
            Exchange::new(&chunk1_send, &[], 0x91, 0x00),
            Exchange::new(&chunk2_send, &[], 0x91, 0x00),
        ]);

        let session =
            block_on(Session::new().authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a))
                .expect("AES auth must succeed");

        block_on(session.write_file(&mut transport, File::Ndef, 0, payload))
            .expect("hw plain chunked write must succeed");

        assert_eq!(transport.remaining(), 0);
    }

    /// Hardware-pinned: 256-byte CommMode.Plain `ReadData` of the NDEF
    /// file (`FileNo=02`, AES Key0 session) returns the whole file in a
    /// single `Length = 0` APDU.
    ///
    /// `GetFileSettings` reports `CommMode = 00h`, so the high-level
    /// `read_file` dispatches to `read_data_plain` via the session-layer
    /// chunker, which forwards `length == 0` as a single APDU (plain
    /// responses have no MAC overhead, so 256 bytes fit `Le = 256`).
    #[test]
    fn read_file_plain_aes_hardware_capture() {
        let payload = &crate::testing::TEST_PAYLOAD_256;
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("0636412AC9A3F204063279F3925EA41D");

        let auth_part1_send = hex_bytes("9071000005000300000000");
        let auth_part1_resp = hex_bytes("EB757B98C848A60815F57A76CC9E9417");
        let auth_part2_send = hex_bytes(
            "90AF000020996C39A0A5278C1E99E9E4EC580FDC1BF76004238FCE41D0C7F8820299BEB50B\
             00",
        );
        let auth_part2_resp =
            hex_bytes("EBCF5E825E7464D9D67CAC08883C342E03C2AAC12415EBFEFE200FEDB8DAB70F");

        let get_file_settings_send = hex_bytes("90F5000009027E0C693A682D1DA600");
        let get_file_settings_resp = hex_bytes("0000E0EE000100F325B6B92B9F5E72");

        // Plain ReadData with Length = 0 — no MAC, fits a single APDU.
        let read_send = hex_bytes("90AD0000070200000000000000");

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&auth_part1_send, &auth_part1_resp, 0x91, 0xAF),
            Exchange::new(&auth_part2_send, &auth_part2_resp, 0x91, 0x00),
            Exchange::new(&get_file_settings_send, &get_file_settings_resp, 0x91, 0x00),
            Exchange::new(&read_send, payload, 0x91, 0x00),
        ]);

        let session =
            block_on(Session::new().authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a))
                .expect("AES auth must succeed");

        let mut buf = [0u8; 256];
        let (n, _session) = block_on(session.read_file(&mut transport, File::Ndef, 0, 0, &mut buf))
            .expect("hw plain read must succeed");

        assert_eq!(n, 256);
        assert_eq!(&buf, payload);
        assert_eq!(transport.remaining(), 0);
    }

    /// Hardware-pinned: 256-byte CommMode.MAC `WriteData` to the NDEF
    /// file (`FileNo=02`, AES Key0 session) splits at the 240-byte
    /// plaintext boundary.
    ///
    /// The trace was captured against an NDEF file whose access rights
    /// require Key0 for writes (so the tag enforces MAC mode rather than
    /// Free access). The replay covers `SELECT_NDEF_APP`,
    /// `AuthenticateEV2First` parts 1+2, `GetFileSettings`, and the two
    /// chunked `WriteData` APDUs — all wire bytes are deterministic
    /// given (factory-default all-zero key, captured `rnd_a`, captured
    /// auth responses), so the library must emit byte-for-byte the same
    /// PCD payloads.
    ///
    /// Asserts (a) the full 6-APDU sequence is emitted in order,
    /// (b) per-chunk `MACt` matches the hardware capture, and
    /// (c) the chunker splits at the MAC-mode boundary
    /// (`Length=0xF0=240` in chunk 1, `Length=0x10=16` in chunk 2).
    #[test]
    fn write_file_mac_chunked_aes_hardware_capture() {
        let payload = &crate::testing::TEST_PAYLOAD_256;
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("3B9EF436D1E3B0C61F0BF0A62B58ABFE");

        let auth_part1_send = hex_bytes("9071000005000300000000");
        let auth_part1_resp = hex_bytes("953BB4EFF9647E09610804B5181F937F");
        let auth_part2_send = hex_bytes(
            "90AF000020C9B3B3D5F73D6EDC1E63B1D69133D2E1C96C2DB567EA65D8F559505417890509\
             00",
        );
        let auth_part2_resp =
            hex_bytes("5EA3D992AA95BF2EDD707EB2EAA2B5E5F08C6D003A399A72AD5CF7AFCCFAB79D");

        let get_file_settings_send = hex_bytes("90F500000902F3A4EFA40FD8B33400");
        let get_file_settings_resp = hex_bytes("0001E0000001008747A1175A459A2E");

        // Chunk 1: 90 8D 00 00 FF | 02 00 00 00 F0 00 00 | data[0..240] | MAC(8) | 00
        let mut chunk1_send = vec![0x90, 0x8D, 0x00, 0x00, 0xFF];
        chunk1_send.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00]);
        chunk1_send.extend_from_slice(&payload[..240]);
        chunk1_send.extend_from_slice(&hex_bytes("ACD771FB4CA1B7BF"));
        chunk1_send.push(0x00);
        let chunk1_resp = hex_bytes("DD5F5452ABB351CB");

        // Chunk 2: 90 8D 00 00 1F | 02 F0 00 00 10 00 00 | data[240..256] | MAC(8) | 00
        let mut chunk2_send = vec![0x90, 0x8D, 0x00, 0x00, 0x1F];
        chunk2_send.extend_from_slice(&[0x02, 0xF0, 0x00, 0x00, 0x10, 0x00, 0x00]);
        chunk2_send.extend_from_slice(&payload[240..]);
        chunk2_send.extend_from_slice(&hex_bytes("3BDEBDCECFA24846"));
        chunk2_send.push(0x00);
        let chunk2_resp = hex_bytes("E878EBA82A564C45");

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&auth_part1_send, &auth_part1_resp, 0x91, 0xAF),
            Exchange::new(&auth_part2_send, &auth_part2_resp, 0x91, 0x00),
            Exchange::new(&get_file_settings_send, &get_file_settings_resp, 0x91, 0x00),
            Exchange::new(&chunk1_send, &chunk1_resp, 0x91, 0x00),
            Exchange::new(&chunk2_send, &chunk2_resp, 0x91, 0x00),
        ]);

        let session =
            block_on(Session::new().authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a))
                .expect("AES auth must succeed");

        block_on(session.write_file(&mut transport, File::Ndef, 0, payload))
            .expect("hw MAC chunked write must succeed");

        assert_eq!(transport.remaining(), 0);
    }

    /// Hardware-pinned: 256-byte CommMode.MAC `ReadData` of the NDEF
    /// file (`FileNo=02`, AES Key0 session) splits at the 248-byte
    /// boundary.
    ///
    /// Doubles as the on-hardware regression test for the `length=0`
    /// MAC-read fix: the previous code path emitted a single
    /// `Length=0` APDU, which the tag rejects with `91 7E LengthError`
    /// once the response would exceed `Le=256`. The captured trace
    /// shows the post-fix wire format: two explicit-length APDUs at
    /// `Length=0xF8=248` and `Length=0x08`, each carrying its own
    /// `MACt` and response trailer.
    #[test]
    fn read_file_mac_chunked_aes_hardware_capture() {
        let payload = &crate::testing::TEST_PAYLOAD_256;
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("90EFB639E594F91F7C72ABE86AD72050");

        let auth_part1_send = hex_bytes("9071000005000300000000");
        let auth_part1_resp = hex_bytes("3241CE4F7E481A0C82C2F2C1C7415C25");
        let auth_part2_send = hex_bytes(
            "90AF000020F59D2408DD7DB93152EF29E9818DF337E287C1CC75DFF89ECC1DCD8DF59BA13F\
             00",
        );
        let auth_part2_resp =
            hex_bytes("4B63020904D156633AEDDA18C88372495BEE6529BB9758C8C77801EB66D6BB06");

        let get_file_settings_send = hex_bytes("90F500000902CB1574C478ECA42100");
        let get_file_settings_resp = hex_bytes("0001E000000100334B8729E85DADBD");

        // Chunk 1: 90 AD 00 00 0F | 02 00 00 00 F8 00 00 | MAC(8) | 00
        let chunk1_send = hex_bytes("90AD00000F02000000F8000086ED60FE9ADC58EB00");
        let mut chunk1_resp = payload[..248].to_vec();
        chunk1_resp.extend_from_slice(&hex_bytes("56355EE135C478D2"));

        // Chunk 2: 90 AD 00 00 0F | 02 F8 00 00 08 00 00 | MAC(8) | 00
        let chunk2_send = hex_bytes("90AD00000F02F80000080000A41B448B3AB5E7EB00");
        let mut chunk2_resp = payload[248..].to_vec();
        chunk2_resp.extend_from_slice(&hex_bytes("7A9BFA4BC24103A2"));

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&auth_part1_send, &auth_part1_resp, 0x91, 0xAF),
            Exchange::new(&auth_part2_send, &auth_part2_resp, 0x91, 0x00),
            Exchange::new(&get_file_settings_send, &get_file_settings_resp, 0x91, 0x00),
            Exchange::new(&chunk1_send, &chunk1_resp, 0x91, 0x00),
            Exchange::new(&chunk2_send, &chunk2_resp, 0x91, 0x00),
        ]);

        let session =
            block_on(Session::new().authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a))
                .expect("AES auth must succeed");

        let mut buf = [0u8; 256];
        let (n, _session) = block_on(session.read_file(&mut transport, File::Ndef, 0, 0, &mut buf))
            .expect("hw MAC chunked read must succeed");

        assert_eq!(n, 256);
        assert_eq!(&buf, payload);
        assert_eq!(transport.remaining(), 0);
    }

    /// Hardware-pinned: 256-byte CommMode.FULL `WriteData` to the NDEF
    /// file (`FileNo=02`, AES Key0 session) splits at the 239-byte
    /// plaintext boundary (240-byte ciphertext after M2 padding).
    ///
    /// Same shape as [`write_file_mac_chunked_aes_hardware_capture`] but
    /// the file's CommMode is FULL — the `GetFileSettings` response
    /// reports `CommMode = 03h`, so the high-level `write_file` dispatches
    /// to the FULL-mode `write_data_full` driver. Chunk 1 sends 239
    /// plaintext bytes (Length=0xEF=239, ciphertext 240 bytes); chunk 2
    /// sends the remaining 17 bytes (Length=0x11=17, ciphertext 32 bytes
    /// after the M2 sentinel forces a second block).
    #[test]
    fn write_file_full_chunked_aes_hardware_capture() {
        let payload = &crate::testing::TEST_PAYLOAD_256;
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("330E8057AB33F30A6ED23C95CDAD08AF");

        let auth_part1_send = hex_bytes("9071000005000300000000");
        let auth_part1_resp = hex_bytes("0A2B841FD910F005B67723949021ABB3");
        let auth_part2_send = hex_bytes(
            "90AF000020A61C9513B6F4F43632A29FC6502F29F0CCAA37105110CFA72484A597472B9283\
             00",
        );
        let auth_part2_resp =
            hex_bytes("42FC380E889753996E0717B7DB575B9020321EFA91015A4B76C72B67F4FBE32A");

        let get_file_settings_send = hex_bytes("90F5000009022904C055CAE7C24E00");
        let get_file_settings_resp = hex_bytes("0003E0000001003F6F50A397B141B1");

        // Chunk 1: 90 8D 00 00 FF | 02 00 00 00 EF 00 00 | E(data[0..239]||80 + zero pad to 240) | MAC(8) | 00
        let chunk1_send = hex_bytes(
            "908D0000FF02000000EF00006BB03EAD7041E930F2193C1B9C21E60012B49C6DF57BCCB009\
             4EAB63FB0CC9A24DEB1154FD7ADF044E36DE1EEF73E3FE6905AF154614E30C51E9CEBE6F72\
             86BC096B473703E360ECFD9E73CEC698D8FE6FF08F3140A7499ADEAB69C6F5242E8C6BA86C\
             4F576DC0806AA0E839053BDF76D23375ECC7DE8C94A6A18E2AD7CC182ED62EFB081BD40A6C\
             D7EC7C5B59AF543BAF369F5BCFA491A07FF60F5FE83D9477EDCF009F9329FD8D08E6018185\
             699E4A8315E7F944A7A77C3F2DCCC37194D5ECA4A38C72B5A491EC6978E44B7AA58B09E156\
             914BF87630AF7D537BF3BE2A5FC3798CD93229F829F4947C03507F2767E873A8346EE3A8BB\
             A300",
        );
        let chunk1_resp = hex_bytes("9E186323844C8634");

        // Chunk 2: 90 8D 00 00 2F | 02 EF 00 00 11 00 00 | E(data[239..256]||80 + zero pad to 32) | MAC(8) | 00
        let chunk2_send = hex_bytes(
            "908D00002F02EF00001100008D6433F11795924DF78DB31BF93F9F0CCDCC2D1DD1C7A20E7B\
             D89D019B3915AAF847F4AA182E5ABD00",
        );
        let chunk2_resp = hex_bytes("C0914E2056D7253F");

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&auth_part1_send, &auth_part1_resp, 0x91, 0xAF),
            Exchange::new(&auth_part2_send, &auth_part2_resp, 0x91, 0x00),
            Exchange::new(&get_file_settings_send, &get_file_settings_resp, 0x91, 0x00),
            Exchange::new(&chunk1_send, &chunk1_resp, 0x91, 0x00),
            Exchange::new(&chunk2_send, &chunk2_resp, 0x91, 0x00),
        ]);

        let session =
            block_on(Session::new().authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a))
                .expect("AES auth must succeed");

        block_on(session.write_file(&mut transport, File::Ndef, 0, payload))
            .expect("hw FULL chunked write must succeed");

        assert_eq!(transport.remaining(), 0);
    }

    /// Hardware-pinned: 256-byte CommMode.FULL `ReadData` of the NDEF
    /// file (`FileNo=02`, AES Key0 session) splits at the 239-byte
    /// plaintext boundary (240-byte ciphertext after M2 padding).
    ///
    /// Same shape as [`read_file_mac_chunked_aes_hardware_capture`] but
    /// the file's CommMode is FULL. Chunk 1 reads 239 plaintext bytes
    /// (Length=0xEF=239, response 248 bytes = 240 ciphertext + 8 MAC);
    /// chunk 2 reads the remaining 17 bytes (Length=0x11=17, response 40
    /// bytes = 32 ciphertext + 8 MAC).
    #[test]
    fn read_file_full_chunked_aes_hardware_capture() {
        let payload = &crate::testing::TEST_PAYLOAD_256;
        let key = [0u8; 16];
        let rnd_a = hex_array::<16>("EC2E171B026A8C1893175DFFF206A0D0");

        let auth_part1_send = hex_bytes("9071000005000300000000");
        let auth_part1_resp = hex_bytes("C213EB5AE1237C03B38309DE66DB2FB1");
        let auth_part2_send = hex_bytes(
            "90AF0000203BD965D97D200D12E66EBD5BE1CA7CB328CEAB51523BA03C43A159A8761D9973\
             00",
        );
        let auth_part2_resp =
            hex_bytes("D94FA833917E526D3048878F373DF76D7F7A9D774473E34C9EDC575D22FD0A3C");

        let get_file_settings_send = hex_bytes("90F500000902208EA076654D3CB200");
        let get_file_settings_resp = hex_bytes("0003E0000001006273E9417D9319DD");

        // Chunk 1: 90 AD 00 00 0F | 02 00 00 00 EF 00 00 | MAC(8) | 00
        let chunk1_send = hex_bytes("90AD00000F02000000EF0000C4B01D43316654B900");
        let chunk1_resp = hex_bytes(
            "4183A86CDDD406563B073B58BAABE7F2D9AD9A2BAEE3E149C05D8EE3A0179BB54380D70CEF\
             E3474456C188ECB6C53235CCE017DD80C24C84F6154EE9A27709C27F71ED2C280CAF9BA03A\
             908704FE4DE6F28C37B8F34D89749D8B9B3701085C5CF75CC4533387778542023CE14B18CF\
             F98AEDF5F81FC93E47B4CC83CA737ECBAC4F95E5C8369E8C24B38C3C22A89BFAB80FCEB156\
             EC11FC3ED1B866CAE6D02817190081837038DE332FD7AD10D153C09C33C0162DBAF6976D57\
             7A95C8482F151192640628BE47B34E274BF54C51E197F03720A21497A56A2CE6FACF4225EF\
             AAE2292E1332C24E53EBC1FFCD75FB9D7E3C35A3980F734626B3",
        );

        // Chunk 2: 90 AD 00 00 0F | 02 EF 00 00 11 00 00 | MAC(8) | 00
        let chunk2_send = hex_bytes("90AD00000F02EF000011000038E030C2E650E02100");
        let chunk2_resp = hex_bytes(
            "029B74B7314E8284F7A80F91D571164D98C737D3951C9EE32275E7A2DAA792030A848C97B6\
             624BBD",
        );

        let mut transport = TestTransport::new([
            Exchange::new(&SELECT_NDEF_APP, &[], 0x90, 0x00),
            Exchange::new(&auth_part1_send, &auth_part1_resp, 0x91, 0xAF),
            Exchange::new(&auth_part2_send, &auth_part2_resp, 0x91, 0x00),
            Exchange::new(&get_file_settings_send, &get_file_settings_resp, 0x91, 0x00),
            Exchange::new(&chunk1_send, &chunk1_resp, 0x91, 0x00),
            Exchange::new(&chunk2_send, &chunk2_resp, 0x91, 0x00),
        ]);

        let session =
            block_on(Session::new().authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a))
                .expect("AES auth must succeed");

        let mut buf = [0u8; 256];
        let (n, _session) = block_on(session.read_file(&mut transport, File::Ndef, 0, 0, &mut buf))
            .expect("hw FULL chunked read must succeed");

        assert_eq!(n, 256);
        assert_eq!(&buf, payload);
        assert_eq!(transport.remaining(), 0);
    }
}
