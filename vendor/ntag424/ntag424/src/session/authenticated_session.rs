use core::future::Future;

use super::Unauthenticated;
#[cfg(feature = "originality")]
use crate::crypto::originality::OriginalitySignature;
use crate::{
    CommMode, Configuration, File, FileSettingsUpdate, FileSettingsView, KeyNumber,
    NonMasterKeyNumber, Session, SessionError, TagTamperStatusReadout, Transport, Version,
    types::file_settings::CryptoMode,
};

/// # Value semantics and command-counter safety
///
/// Most authenticated commands consume `self` and return it only on success.
/// On the PICC, successful authenticated-session commands advance the shared
/// `CmdCtr`, including commands sent with plain wire framing. MAC-protected
/// and encrypted commands additionally derive or verify secure-messaging data
/// from the current counter value. If a command fails, the host cannot in
/// general know whether the PICC already advanced its counter, so continuing
/// to use the old session could desynchronise secure messaging.
///
/// Taking ownership of the session makes this explicit: on error the caller
/// loses the session and must re-authenticate.
///
/// The plain authenticated helpers [`Self::read_file_plain`] and
/// [`Self::write_file_plain`] take `&mut self` instead because the APDU
/// framing itself is plain: no request or response MAC is computed or
/// verified. A successful call still advances the tracked counter so the
/// host stays aligned with the PICC.
pub trait AuthenticatedSession: Sized {
    /// Return the session's crypto mode.
    fn mode(&self) -> CryptoMode;

    /// Return the key number used for authentication.
    fn key_number(&self) -> KeyNumber;

    /// Read software, hardware and production version information.
    ///
    /// Uses MAC mode communication. Consumes `self` and returns it on success
    /// because the MAC exchange advances the secure channel's command counter;
    /// losing the session on error prevents counter desynchronisation.
    fn get_version<T: Transport>(
        self,
        transport: &mut T,
    ) -> impl Future<Output = Result<(Version, Self), SessionError<T::Error>>>;

    /// Change a non-master application key.
    ///
    /// The factory default value for all keys is `[0u8; 16]`.
    ///
    /// Authentication with the master key must be established before calling this.
    ///
    /// To change the master key use [`Self::change_master_key`] instead.
    fn change_key<T: Transport>(
        self,
        transport: &mut T,
        key_no: NonMasterKeyNumber,
        new_key: &[u8; 16],
        new_key_version: u8,
        old_key: &[u8; 16],
    ) -> impl Future<Output = Result<Self, SessionError<T::Error>>>;

    /// Change the application master key.
    ///
    /// Authentication with the master key must be established before calling this.
    ///
    /// After this call the session keys are
    /// no longer valid for any further command, so the session is
    /// consumed and an unauthenticated one is returned. Re-run the
    /// authentication to issue further
    /// authenticated commands.
    fn change_master_key<T: Transport>(
        self,
        transport: &mut T,
        new_key: &[u8; 16],
        new_key_version: u8,
    ) -> impl Future<Output = Result<Session<Unauthenticated>, SessionError<T::Error>>>;

    /// Read the permanent tag UID.
    ///
    /// Returns the permanent UID even when the tag is configured for Random ID
    /// at activation (NT4H2421Gx §10.5.3). This is in contrast to the unauthenticated
    /// [`get_selected_uid`](`Session::get_selected_uid`) which will
    /// return the random ID if used.
    fn get_uid<T: Transport>(
        self,
        transport: &mut T,
    ) -> impl Future<Output = Result<([u8; 7], Self), SessionError<T::Error>>>;

    /// Read an application key version.
    ///
    /// Returns `0` for disabled keys and for the originality key (not
    /// implemented), and the full byte range otherwise.
    fn get_key_version<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
    ) -> impl Future<Output = Result<(u8, Self), SessionError<T::Error>>>;

    /// Read file settings.
    ///
    /// This is the recommended starting point before calling
    /// [`Self::change_file_settings`]: convert the returned
    /// [`FileSettingsView`] with [`FileSettingsView::into_update`] and then
    /// modify that update. `ChangeFileSettings` overwrites all mutable fields,
    /// so starting from the current view helps avoid accidentally replacing
    /// access rights or communication mode while changing SDM.
    fn get_file_settings<T: Transport>(
        self,
        transport: &mut T,
        file: File,
    ) -> impl Future<Output = Result<(FileSettingsView, Self), SessionError<T::Error>>>;

    /// Read a file's SDM read counter.
    ///
    /// The counter increments on unauthenticated reads of the file when SDM
    /// is enabled, it is reset to zero when enabling SDM for the file.
    fn get_file_counters<T: Transport>(
        self,
        transport: &mut T,
        file: File,
    ) -> impl Future<Output = Result<(u32, Self), SessionError<T::Error>>>;

    /// Read the TagTamper permanent and current status bytes.
    ///
    /// On TagTamper-capable silicon, `Invalid` indicates the feature exists
    /// but has not been enabled yet (NT4H2421Gx §10.5.5).
    fn get_tt_status<T: Transport>(
        self,
        transport: &mut T,
    ) -> impl Future<Output = Result<(TagTamperStatusReadout, Self), SessionError<T::Error>>>;

    /// Apply tag configuration changes.
    ///
    /// Authentication with the application master key must be
    /// established before calling this. Each option set on `configuration`
    /// is sent as its own APDU (the command is single-option per call) in
    /// the canonical order. A configuration with no options is a no-op.
    ///
    /// Enabling LRP is intentionally not reachable through this method —
    /// the tag tears down the secure channel as part of the switch, so
    /// mixing it with other options would leave the session in an invalid
    /// state. Use [`Session::enable_lrp`] instead, which consumes the
    /// authenticated AES session and returns a fresh unauthenticated one.
    ///
    /// Several options are irreversible, see [`Configuration`] for the
    /// individual `with_*` builder methods.
    fn set_configuration<T: Transport>(
        self,
        transport: &mut T,
        configuration: &Configuration,
    ) -> impl Future<Output = Result<Self, SessionError<T::Error>>>;

    /// Change a file's settings.
    ///
    /// Authentication with the key indicated by the file's `Change` access
    /// condition must be established before calling this.
    ///
    /// When changing the NDEF file's access conditions, also update the
    /// Capability Container ([`File::CapabilityContainer`]) so that NFC Forum
    /// readers see an accurate T4T mapping. The high-level
    /// [`provision`](`crate::high_level::provision`) functions do this automatically.
    fn change_file_settings<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        settings: &FileSettingsUpdate,
    ) -> impl Future<Output = Result<Self, SessionError<T::Error>>>;

    /// Verify the tag's NXP originality signature against the UID.
    ///
    /// Reads the ECDSA signature stored on the tag and verifies it against
    /// the NXP master public key (AN12196 §7.2), confirming the tag was
    /// manufactured by NXP. On success returns the session and the verified
    /// [`OriginalitySignature`] so the caller can inspect or store the raw
    /// signature bytes.
    ///
    /// Requires the `originality` feature (default-on).
    #[cfg(feature = "originality")]
    fn verify_originality<T: Transport>(
        self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> impl Future<Output = Result<(Self, OriginalitySignature), SessionError<T::Error>>>;

    /// Read file bytes in plain mode.
    ///
    /// This must be used when the only access
    /// condition granting the current session access is free access.
    /// The APDU itself is sent in plain framing, but a successful authenticated-
    /// session read still advances the tracked command counter.
    ///
    /// `length = 0` means "entire file from `offset`". Returns the
    /// number of bytes copied into `buf`.
    fn read_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, SessionError<T::Error>>>;

    /// Read file bytes with an explicit communication mode.
    ///
    /// Reads `length` bytes from `file` starting at `offset`, using the
    /// caller-supplied `mode` as the command's effective communication mode.
    ///
    /// The required communication mode can be determined by the file's configuration,
    /// with one exception: when the
    /// only access condition granting the current session access to the
    /// targeted right (`Read` / `ReadWrite` / SDM file-read) is free
    /// access, plain communication mode must be used even though the
    /// session is authenticated. You may use [`Self::read_file_plain`]
    /// in this case.
    ///
    /// `length = 0` means "entire file from `offset`", capped at the
    /// 256-byte short-Le response limit (NT4H2421Gx §10.8.1). When
    /// `length != 0`, `buf.len()` must be at least `length`.
    ///
    /// This method consumes `self` and returns it on success because all
    /// successful authenticated-session reads advance the shared command
    /// counter, even when the wire framing is plain. MAC and Full modes also
    /// derive or verify secure-messaging data from that counter; Plain mode
    /// is included here for a uniform return type. Use [`Self::read_file_plain`]
    /// when you specifically want plain framing.
    fn read_file_with_mode<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        mode: CommMode,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(usize, Self), SessionError<T::Error>>>;

    /// Write file bytes in plain communication mode.
    ///
    /// This must be used when the only access
    /// condition granting the current session access is free access.
    /// The APDU itself is sent in plain framing, but a successful authenticated-
    /// session write still advances the tracked command counter.
    fn write_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<(), SessionError<T::Error>>>;

    /// Write file bytes with an explicit communication mode.
    ///
    /// Writes `data` to `file` starting at `offset`, using the
    /// caller-supplied `mode` as the command's effective communication mode.
    ///
    /// The required communication mode can be determined by the file's configuration,
    /// with one exception: when the
    /// only access condition granting the current session access to the
    /// targeted right (read / write) is free access,
    /// plain communication mode must be used even though the session is
    /// authenticated. You may use [`Self::write_file_plain`]
    /// in this case.
    ///
    /// This method consumes `self` and returns it on success because all
    /// successful authenticated-session writes advance the shared command
    /// counter, even when the wire framing is plain. MAC and Full modes also
    /// derive or verify secure-messaging data from that counter; Plain mode
    /// is included here for a uniform return type. Use [`Self::write_file_plain`]
    /// when you specifically want plain framing.
    fn write_file_with_mode<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
        mode: CommMode,
    ) -> impl Future<Output = Result<Self, SessionError<T::Error>>>;

    /// Write file bytes.
    ///
    /// This is a convenience wrapper around [`Self::write_file_with_mode`] that
    /// determines the communication mode from the file settings. It uses
    /// [`Self::get_file_settings`] to read the correct mode.
    ///
    /// If you already know the required mode you should use
    /// [`Self::write_file_with_mode`] directly to avoid the extra round trip.
    fn write_file<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<Self, SessionError<T::Error>>>;

    /// Read file bytes.
    ///
    /// This is a convenience wrapper around [`Self::read_file_with_mode`] that
    /// determines the communication mode from the file settings. It uses
    /// [`Self::get_file_settings`] to read the correct mode.
    ///
    /// If you already know the required mode you should use
    /// [`Self::read_file_with_mode`] directly to avoid the extra round trip.
    fn read_file<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(usize, Self), SessionError<T::Error>>>;

    /// Return the session transaction identifier.
    ///
    /// This value is assigned by the tag on the first authentication
    /// of the transaction (NT4H2421Gx §9.1.1).
    #[doc(hidden)] // not needed by typical users, but exposed for advanced use cases and testing
    fn ti(&self) -> &[u8; 4];

    #[doc(hidden)]
    fn pd_cap2(&self) -> &[u8; 6];

    /// Return the tag's capabilities as observed during authentication.
    ///
    /// The last two bytes can be set with
    /// [`Configuration::with_pdcap2_5`](`crate::types::Configuration::with_pdcap2_5`) and
    /// [`Configuration::with_pdcap2_6`](`crate::types::Configuration::with_pdcap2_6`) respectively.
    fn pcd_cap2(&self) -> &[u8; 6];

    /// Current value of the shared Command Counter.
    ///
    /// Reset to zero on authentication and advanced in lockstep with
    /// the tag as commands succeed.
    #[doc(hidden)] // not needed by typical users, but exposed for advanced use cases and testing
    fn cmd_counter(&self) -> u16;

    /// Re-authenticate within an existing session.
    ///
    /// Returns `self` with the suite replaced by the newly derived one.
    ///
    /// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy.
    fn authenticate<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> impl Future<Output = Result<Self, SessionError<T::Error>>>;
}
