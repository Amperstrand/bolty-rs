// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// A response status word returned by the tag after processing a command.
pub enum ResponseStatus {
    /// Successful operation.
    OperationOk,
    /// Command code not supported.
    IllegalCommandCode,
    /// CRC or MAC does not match data. Padding bytes not valid.
    IntegrityError,
    /// Invalid key number specified.
    NoSuchKey,
    /// Length of command string invalid.
    LengthError,
    /// Current configuration / status does not allow the requested command.
    PermissionDenied,
    /// Value of the parameter(s) invalid.
    ParameterError,
    /// Currently not allowed to authenticate.
    /// Keep trying until full delay is spent.
    AuthenticationDelay,
    /// Current authentication status does not allow the requested command.
    AuthenticationError,
    /// Additional frame expected to be sent.
    AdditionalFrame,
    /// Attempt to read/write data from/to beyond the file's/record's limits.
    /// Attempt to exceed the limits of a value file.
    BoundaryError,
    /// Previous command was not fully completed. Not all frames were requested or provided by the PCD.
    CommandAborted,
    /// Failure when reading or writing to non-volatile memory.
    MemoryError,
    /// Specified file number does not exist.
    FileNotFound,
    /// ISO 7816-4 `0x6700`: wrong length — no further indication.
    ///
    /// Returned for CLA `0x00` commands when the Lc/Le byte does not match
    /// what the instruction expects (datasheet Table 24).
    ///
    /// Observed in:
    /// - [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated) / [`Session::write_file_unauthenticated`](crate::Session::write_file_unauthenticated):
    ///   wrong or inconsistent APDU length (Tables 89, 92, 95).
    WrongLength,
    /// ISO 7816-4 `0x6982`: security status not satisfied (datasheet Table 24).
    ///
    /// Observed in:
    /// - [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated) (Table 92): access denied
    ///   because Read *and* ReadWrite rights both differ from `0xE` while
    ///   SDMFileRead (if SDM is enabled) is `0xF`; SDMReadCtr overflow;
    ///   SDMReadCtrLimit reached in unauthenticated state; EV2 or LRP
    ///   authentication mode not allowed for this file.
    /// - [`Session::write_file_unauthenticated`](crate::Session::write_file_unauthenticated) (Table 95): only free
    ///   write (Write or ReadWrite = `0xE`) is permitted; EV2 or LRP
    ///   authentication mode not allowed for this file.
    SecurityStatusNotSatisfied,
    /// ISO 7816-4 `0x6985`: conditions of use not satisfied (datasheet Table 24).
    ///
    /// Observed in:
    /// - Any session method that performs an implicit application select
    ///   (Table 89): a wrapped chained or multiple-pass command is already
    ///   ongoing.
    /// - [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated) (Table 92): wrapped
    ///   chained/multiple-pass command ongoing; no file selected; targeted
    ///   file is not a StandardData file; application holds a
    ///   TransactionMAC file.
    /// - [`Session::write_file_unauthenticated`](crate::Session::write_file_unauthenticated) (Table 95): wrapped
    ///   chained/multiple-pass command ongoing; no file selected; attempt
    ///   to write beyond the file boundary set during creation.
    ConditionsOfUseNotSatisfied,
    /// ISO 7816-4 `0x6A80`: incorrect parameters in the command data field.
    ///
    /// The data bytes carried in the command body are invalid or inconsistent.
    /// See datasheet Table 24.
    IncorrectParametersInTheCommandDataField,
    /// ISO 7816-4 `0x6A82`: file or application not found (datasheet Table 24).
    ///
    /// The DF, EF, or application addressed by the command does not exist.
    /// For native NTAG 424 DNA commands see [`ResponseStatus::FileNotFound`].
    ///
    /// Observed in:
    /// - Any session method that performs an implicit application select
    ///   (Table 89): application or file not found; the previously selected
    ///   application remains active.
    /// - [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated) / [`Session::write_file_unauthenticated`](crate::Session::write_file_unauthenticated)
    ///   (Tables 92, 95): EF or DF not found.
    FileOrApplicationNotFound,
    /// ISO 7816-4 `0x6A86`: incorrect parameters P1–P2 (datasheet Table 24).
    ///
    /// Observed in:
    /// - [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated) / [`Session::write_file_unauthenticated`](crate::Session::write_file_unauthenticated)
    ///   and any implicit application select (Tables 89, 92, 95): wrong
    ///   value for P1 and/or P2.
    IncorrectParametersP1P2,
    /// ISO 7816-4 `0x6A87`: Lc inconsistent with parameters P1–P2.
    ///
    /// The command data length (Lc) contradicts the encoding implied by the
    /// P1/P2 bytes (datasheet Table 24).
    ///
    /// Observed in:
    /// - Any session method that performs an implicit application select
    ///   (Table 89): Lc inconsistent with P1-P2.
    LcInconsistentWithParametersP1P2,
    /// ISO 7816-4 `0x6C00`: wrong Le field — exact expected length unknown.
    ///
    /// The Le byte does not match the number of bytes the card would return,
    /// but this `0x6C00` form carries no indication of the correct value.
    /// When the card *does* know the correct length it returns `0x6Cxx`
    /// (`xx` ≠ `00`), which is decoded as
    /// [`ResponseStatus::WrongLeFieldExpected`].
    /// See datasheet Table 24.
    WrongLeField,
    /// ISO 7816-4 `0x6Cxx` (`xx` ≠ `00`): wrong Le field.
    ///
    /// SW2 encodes the exact number of bytes available for the response.
    /// Re-issue the command with `Le = SW2` to retrieve the data.
    /// See datasheet Table 24.
    WrongLeFieldExpected(u8),
    /// ISO 7816-4 `0x6D00`: instruction code not supported or invalid.
    ///
    /// The INS byte of the APDU is not recognised or not valid in the
    /// current context. See datasheet Table 24.
    InstructionCodeNotSupportedOrInvalid,
    /// ISO 7816-4 `0x6E00`: class not supported — wrong CLA byte
    /// (datasheet Table 24).
    ///
    /// Observed in:
    /// - [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated) / [`Session::write_file_unauthenticated`](crate::Session::write_file_unauthenticated)
    ///   and any implicit application select (Tables 89, 92, 95).
    ClassNotSupported,
    /// ISO 7816-4 `0x9000`: normal processing, no further qualification.
    ///
    /// Successful completion of a CLA `0x00` command. See datasheet Table 24.
    NormalProcessing,
    /// Unrecognised status word.
    ///
    /// Carries the raw SW1SW2 value so callers can inspect or log it.
    Unknown(u16),
}
