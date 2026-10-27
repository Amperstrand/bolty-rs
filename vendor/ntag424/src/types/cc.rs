// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Capability Container (CC) file parsing and serialisation.
//!
//! The CC file (File No. `01h`, File ID `E103h`) is a static metadata file
//! that describes the tag's NFC Forum Type 4 Tag capabilities. In normal use
//! you only need this module when you want to inspect or verify the CC
//! contents: read the raw bytes with
//! [`Session::read_file_unauthenticated`](crate::Session::read_file_unauthenticated)
//! (passing [`File::CapabilityContainer`](crate::types::File::CapabilityContainer)),
//! then decode them with [`CapabilityContainer::from_bytes`].
use arrayvec::ArrayVec;
use thiserror::Error;

use super::KeyNumber;

/// Maximum number of File Control entries in a Capability Container.
///
/// NTAG 424 DNA carries two entries (NDEF + proprietary). Three is a
/// safe upper bound for this IC family.
const MAX_CC_FILES: usize = 3;

/// Maximum serialised CC size: 7-byte header + 8 bytes per entry.
const MAX_CC_BYTES: usize = 7 + MAX_CC_FILES * 8;

/// Parsed contents of the NTAG 424 DNA **Capability Container (CC) file**.
///
/// The CC file is a StandardData file (File No. `01h`, File ID `E103h`, 32 bytes
/// on the IC) whose payload follows the NFC Forum Type 4 Tag mapping. See
/// NT4H2421Gx §8.2.3.2.
///
/// Byte layout on the wire:
///
/// | Offset | Size | Field |
/// |-------:|-----:|-------|
/// | 0      | 2    | [`cc_len`](Self::cc_len) |
/// | 2      | 1    | [`t4t_version`](Self::t4t_version) |
/// | 3      | 2    | [`max_le`](Self::max_le) |
/// | 5      | 2    | [`max_lc`](Self::max_lc) |
/// | 7      | *    | one or more [`FileCtrl`] entries |
///
/// All fixed header fields are read-only after parsing; the per-file
/// fields can be mutated via the [`FileCtrl`] setters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityContainer {
    cc_len: u16,
    t4t_version: u8,
    max_le: u16,
    max_lc: u16,
    files: ArrayVec<FileCtrl, MAX_CC_FILES>,
}

/// One File Control entry inside the Capability Container.
///
/// On NTAG 424 DNA each entry is a 6-byte record holding `File ID` (2),
/// `File Size` (2), `READ` (1), `WRITE` (1); see NT4H2421Gx §8.2.3.2
/// (`NDEF-File_Ctrl_TLV` / `Proprietary-File_Ctrl_TLV`).
///
/// Exposed read-only. To rebuild a CC with modified fields, use the
/// `with_*` builder methods on [`CapabilityContainer`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileCtrl {
    kind: FileCtrlKind,
    file_id: u16,
    file_size: u16,
    read_access: AccessCondition,
    write_access: AccessCondition,
}

/// Kind of File Control entry.
///
/// Distinguishes the two file types the NTAG 424 DNA exposes through
/// the T4T mapping.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileCtrlKind {
    /// NDEF File Control entry (on-wire tag `04h`).
    Ndef,
    /// Proprietary File Control entry (on-wire tag `05h`).
    Proprietary,
}

/// READ / WRITE access condition byte of a [`FileCtrl`] entry.
///
/// Encoded per the NFC Forum Type 4 Tag specification (see NT4H2421Gx
/// §8.2.3.2 and \[15\]). This is **not** the 2-byte `Set of Access condition`
/// of §8.2.3.3 used by `ChangeFileSettings`.
///
/// | Byte value     | Meaning |
/// |----------------|---------|
/// | `00h`          | Open access (no authentication) |
/// | `80h` … `84h`  | Proprietary methods, key `0h` … `4h` |
/// | `FFh`          | No access / denied |
/// | anything else  | RFU or other proprietary encoding |
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AccessCondition {
    /// Access granted without authentication (`00h`).
    Open,
    /// Access limited to proprietary methods after authenticating with the
    /// given application key. Encoded as `80h | key_number`.
    ProprietaryKey(KeyNumber),
    /// Access denied (`FFh`).
    Denied,
    /// Any other raw byte value.
    ///
    /// This covers RFU or proprietary encodings not covered by the
    /// variants above. It is produced only by parsing; prefer the named
    /// variants when constructing a value.
    Raw(u8),
}

impl AccessCondition {
    /// Decode a single access-condition byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Open,
            0x80 => Self::ProprietaryKey(KeyNumber::Key0),
            0x81 => Self::ProprietaryKey(KeyNumber::Key1),
            0x82 => Self::ProprietaryKey(KeyNumber::Key2),
            0x83 => Self::ProprietaryKey(KeyNumber::Key3),
            0x84 => Self::ProprietaryKey(KeyNumber::Key4),
            0xFF => Self::Denied,
            other => Self::Raw(other),
        }
    }

    /// Encode as the wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Open => 0x00,
            Self::ProprietaryKey(k) => 0x80 | k.as_byte(),
            Self::Denied => 0xFF,
            Self::Raw(b) => b,
        }
    }
}

impl Default for CapabilityContainer {
    /// Return the factory-default CC content.
    ///
    /// This matches the NXP NTAG 424 DNA default from NT4H2421Gx
    /// §8.2.3.2: NDEF file `E104h` / 256 bytes / open access,
    /// proprietary file `E105h` / 128 bytes / read via key `2h`,
    /// write via key `3h`, mapping version 2.0, `MLe = 256`,
    /// `MLc = 255`.
    fn default() -> Self {
        let mut files = ArrayVec::new();
        files.push(FileCtrl {
            kind: FileCtrlKind::Ndef,
            file_id: 0xE104,
            file_size: 0x0100,
            read_access: AccessCondition::Open,
            write_access: AccessCondition::Open,
        });
        files.push(FileCtrl {
            kind: FileCtrlKind::Proprietary,
            file_id: 0xE105,
            file_size: 0x0080,
            read_access: AccessCondition::ProprietaryKey(KeyNumber::Key2),
            write_access: AccessCondition::ProprietaryKey(KeyNumber::Key3),
        });
        Self {
            cc_len: 0x0017,
            t4t_version: 0x20,
            max_le: 0x0100,
            max_lc: 0x00FF,
            files,
        }
    }
}

impl CapabilityContainer {
    /// Parse a Capability Container from its on-card byte representation.
    ///
    /// `data` is the payload returned by a `ReadBinary` on the CC file
    /// (File ID `E103h`). A file entry whose declared length runs past the
    /// end of `data` is rejected via [`CcError::EntryOverflow`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, CcError> {
        if data.len() < 7 {
            return Err(CcError::TooShort);
        }

        let cc_len = u16::from_be_bytes([data[0], data[1]]);
        let t4t_version = data[2];
        let max_le = u16::from_be_bytes([data[3], data[4]]);
        let max_lc = u16::from_be_bytes([data[5], data[6]]);

        let mut files = ArrayVec::new();
        let mut offset = 7;
        let limit = (cc_len as usize).min(data.len());

        while offset < limit {
            if offset + 2 > limit {
                break;
            }

            let t = data[offset];
            let l = data[offset + 1] as usize;
            offset += 2;

            if offset + l > limit {
                return Err(CcError::EntryOverflow);
            }

            let kind = match t {
                0x04 => FileCtrlKind::Ndef,
                0x05 => FileCtrlKind::Proprietary,
                _ => return Err(CcError::UnknownEntryTag(t)),
            };

            if l != 6 {
                return Err(CcError::UnexpectedEntryLength(l));
            }

            let entry = &data[offset..offset + l];
            files
                .try_push(FileCtrl {
                    kind,
                    file_id: u16::from_be_bytes([entry[0], entry[1]]),
                    file_size: u16::from_be_bytes([entry[2], entry[3]]),
                    read_access: AccessCondition::from_byte(entry[4]),
                    write_access: AccessCondition::from_byte(entry[5]),
                })
                .map_err(|_| CcError::TooManyEntries)?;

            offset += l;
        }

        Ok(Self {
            cc_len,
            t4t_version,
            max_le,
            max_lc,
            files,
        })
    }

    /// Serialise the CC back into its on-card byte representation.
    pub fn to_bytes(&self) -> ArrayVec<u8, MAX_CC_BYTES> {
        let mut out = ArrayVec::new();

        out.try_extend_from_slice(&self.cc_len.to_be_bytes())
            .unwrap();
        out.push(self.t4t_version);
        out.try_extend_from_slice(&self.max_le.to_be_bytes())
            .unwrap();
        out.try_extend_from_slice(&self.max_lc.to_be_bytes())
            .unwrap();

        for file in self.files() {
            out.push(match file.kind {
                FileCtrlKind::Ndef => 0x04,
                FileCtrlKind::Proprietary => 0x05,
            });
            out.push(0x06); // length is always 6
            out.try_extend_from_slice(&file.file_id.to_be_bytes())
                .unwrap();
            out.try_extend_from_slice(&file.file_size.to_be_bytes())
                .unwrap();
            out.push(file.read_access.to_byte());
            out.push(file.write_access.to_byte());
        }

        out
    }

    /// Total length of the CC data in bytes (`CCLEN`). At delivery this is
    /// `0x0017` (23 bytes) covering the header and the two file entries.
    pub fn cc_len(&self) -> u16 {
        self.cc_len
    }

    /// Raw T4T mapping version byte (`T4T_VNo`). Ships as `0x20`
    /// (Mapping Version 2.0). Use [`version_major`](Self::version_major) /
    /// [`version_minor`](Self::version_minor) for the decoded digits.
    pub fn t4t_version(&self) -> u8 {
        self.t4t_version
    }

    /// Major digit of the T4T mapping version (high nibble of `T4T_VNo`).
    pub fn version_major(&self) -> u8 {
        self.t4t_version >> 4
    }

    /// Minor digit of the T4T mapping version (low nibble of `T4T_VNo`).
    pub fn version_minor(&self) -> u8 {
        self.t4t_version & 0x0F
    }

    /// Return the CC's `MLe` value.
    ///
    /// This is the maximum number of bytes the PICC may return in a
    /// single `ReadBinary` response. The default is `0x0100` (256).
    pub fn max_le(&self) -> u16 {
        self.max_le
    }

    /// Maximum number of bytes the PICC accepts in a single `UpdateBinary`
    /// command (`MLc`). Defaults to `0x00FF` (255).
    pub fn max_lc(&self) -> u16 {
        self.max_lc
    }

    /// File Control entries describing each EF reachable through the T4T
    /// mapping. On NTAG 424 DNA this is always the NDEF file followed by
    /// the proprietary file.
    pub fn files(&self) -> &[FileCtrl] {
        &self.files
    }

    /// Replace the NDEF file's READ access condition.
    pub fn with_ndef_read_access(mut self, access: AccessCondition) -> Self {
        if let Some(f) = self.find_mut(FileCtrlKind::Ndef) {
            f.read_access = access;
        }
        self
    }

    /// Replace the NDEF file's WRITE access condition.
    pub fn with_ndef_write_access(mut self, access: AccessCondition) -> Self {
        if let Some(f) = self.find_mut(FileCtrlKind::Ndef) {
            f.write_access = access;
        }
        self
    }

    /// Replace the proprietary file's READ access condition.
    pub fn with_proprietary_read_access(mut self, access: AccessCondition) -> Self {
        if let Some(f) = self.find_mut(FileCtrlKind::Proprietary) {
            f.read_access = access;
        }
        self
    }

    /// Replace the proprietary file's WRITE access condition.
    pub fn with_proprietary_write_access(mut self, access: AccessCondition) -> Self {
        if let Some(f) = self.find_mut(FileCtrlKind::Proprietary) {
            f.write_access = access;
        }
        self
    }

    /// Replace the NDEF file's File Size.
    ///
    /// This is the file's **maximum capacity** (set at IC personalisation),
    /// not its current payload length - writing into the file does **not**
    /// change this value and neither should this builder. Use it only when
    /// rebuilding a CC for an IC configured with non-default sizes (e.g.
    /// after extending the NDEF file via `SetConfiguration` option `0Ah`).
    /// The value does not reach the card's internal file table.
    pub fn with_ndef_file_size(mut self, file_size: u16) -> Self {
        if let Some(f) = self.find_mut(FileCtrlKind::Ndef) {
            f.file_size = file_size;
        }
        self
    }

    /// Replace the proprietary file's File Size. See
    /// [`with_ndef_file_size`](Self::with_ndef_file_size) for the
    /// maximum-capacity-vs-payload caveat.
    pub fn with_proprietary_file_size(mut self, file_size: u16) -> Self {
        if let Some(f) = self.find_mut(FileCtrlKind::Proprietary) {
            f.file_size = file_size;
        }
        self
    }

    fn find_mut(&mut self, kind: FileCtrlKind) -> Option<&mut FileCtrl> {
        self.files.iter_mut().find(|f| f.kind == kind)
    }
}

impl FileCtrl {
    /// Which kind of entry this is (NDEF vs. proprietary).
    pub fn kind(&self) -> FileCtrlKind {
        self.kind
    }

    /// 16-bit ISO/IEC 7816-4 File Identifier of the referenced EF. Defaults:
    /// `E104h` (NDEF file) and `E105h` (proprietary file).
    pub fn file_id(&self) -> u16 {
        self.file_id
    }

    /// Size of the referenced EF in bytes. Defaults: `0100h` (256) for the
    /// NDEF file, `0080h` (128) for the proprietary file.
    pub fn file_size(&self) -> u16 {
        self.file_size
    }

    /// READ access condition for this file. Defaults to
    /// [`AccessCondition::Open`] on the NDEF file and
    /// `ProprietaryKey(Key2)` on the proprietary file.
    pub fn read_access(&self) -> AccessCondition {
        self.read_access
    }

    /// WRITE access condition for this file. Defaults to
    /// [`AccessCondition::Open`] on the NDEF file and
    /// `ProprietaryKey(Key3)` on the proprietary file.
    pub fn write_access(&self) -> AccessCondition {
        self.write_access
    }
}

/// Errors returned when parsing a Capability Container.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CcError {
    /// The input is shorter than the 7-byte CC header.
    #[error("CC data too short")]
    TooShort,
    /// A file entry overruns the input.
    #[error("file entry extends beyond CC data")]
    EntryOverflow,
    /// Encountered an entry tag other than `04h` (NDEF) or `05h` (Proprietary).
    #[error("unknown file entry tag: {0:#04x}")]
    UnknownEntryTag(u8),
    /// A File Control entry did not carry the required 6-byte value.
    #[error("unexpected file entry length: {0}")]
    UnexpectedEntryLength(usize),
    /// More file entries than the fixed-capacity buffer supports.
    #[error("too many file entries")]
    TooManyEntries,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The NTAG 424 default CC file content
    const NTAG424_DEFAULT_CC: [u8; 23] = [
        0x00, 0x17, // CCLEN = 23
        0x20, // T4T_VNo = 2.0
        0x01, 0x00, // MLe = 256
        0x00, 0xFF, // MLc = 255
        // NDEF-File_Ctrl_TLV
        0x04, 0x06, // T=04, L=06
        0xE1, 0x04, // File ID
        0x01, 0x00, // File Size = 256
        0x00, // READ access: open
        0x00, // WRITE access: open
        // Proprietary-File_Ctrl_TLV
        0x05, 0x06, // T=05, L=06
        0xE1, 0x05, // File ID
        0x00, 0x80, // File Size = 128
        0x82, // READ access: key 2
        0x83, // WRITE access: key 3
    ];

    #[test]
    fn decode_ntag424_default() {
        let cc = CapabilityContainer::from_bytes(&NTAG424_DEFAULT_CC).unwrap();
        assert_eq!(cc.cc_len(), 0x0017);
        assert_eq!(cc.version_major(), 2);
        assert_eq!(cc.version_minor(), 0);
        assert_eq!(cc.max_le(), 256);
        assert_eq!(cc.max_lc(), 255);
        assert_eq!(cc.files().len(), 2);

        let ndef = &cc.files()[0];
        assert_eq!(ndef.kind(), FileCtrlKind::Ndef);
        assert_eq!(ndef.file_id(), 0xE104);
        assert_eq!(ndef.file_size(), 256);
        assert_eq!(ndef.read_access(), AccessCondition::Open);
        assert_eq!(ndef.write_access(), AccessCondition::Open);

        let prop = &cc.files()[1];
        assert_eq!(prop.kind(), FileCtrlKind::Proprietary);
        assert_eq!(prop.file_id(), 0xE105);
        assert_eq!(prop.file_size(), 128);
        assert_eq!(
            prop.read_access(),
            AccessCondition::ProprietaryKey(KeyNumber::Key2)
        );
        assert_eq!(
            prop.write_access(),
            AccessCondition::ProprietaryKey(KeyNumber::Key3)
        );
    }

    #[test]
    fn roundtrip() {
        let cc = CapabilityContainer::from_bytes(&NTAG424_DEFAULT_CC).unwrap();
        assert_eq!(*cc.to_bytes(), NTAG424_DEFAULT_CC);
    }

    #[test]
    fn default_matches_delivery_bytes() {
        let cc = CapabilityContainer::default();
        assert_eq!(*cc.to_bytes(), NTAG424_DEFAULT_CC,);
        assert_eq!(
            CapabilityContainer::default(),
            CapabilityContainer::from_bytes(&NTAG424_DEFAULT_CC).unwrap(),
        );
    }

    #[test]
    fn builder_chain_changes_access() {
        let cc = CapabilityContainer::default()
            .with_ndef_write_access(AccessCondition::Denied)
            .with_proprietary_read_access(AccessCondition::ProprietaryKey(KeyNumber::Key1));

        let bytes = cc.to_bytes();
        assert_eq!(bytes[14], 0xFF); // NDEF WRITE byte flipped to denied
        assert_eq!(bytes[21], 0x81); // Proprietary READ byte now key 1

        let parsed = CapabilityContainer::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.files()[0].write_access(), AccessCondition::Denied);
        assert_eq!(
            parsed.files()[1].read_access(),
            AccessCondition::ProprietaryKey(KeyNumber::Key1)
        );
    }

    #[test]
    fn access_condition_byte_roundtrip() {
        for byte in 0u8..=0xFF {
            let ac = AccessCondition::from_byte(byte);
            assert_eq!(ac.to_byte(), byte, "byte {byte:#04x} did not round-trip");
        }
    }

    /// Parse a full 32-byte CC file image.
    ///
    /// The bytes come from a real NTAG 424 DNA tag via `ISOReadBinary`
    /// (EF `E103h`). The first 23 bytes are the CC data (matching
    /// [`NTAG424_DEFAULT_CC`]); the remaining bytes are zero padding.
    #[test]
    fn decode_full_cc_file_from_hardware() {
        #[rustfmt::skip]
        let cc_file: [u8; 32] = [
            0x00, 0x17, 0x20, 0x01, 0x00, 0x00, 0xFF, 0x04,
            0x06, 0xE1, 0x04, 0x01, 0x00, 0x00, 0x00, 0x05,
            0x06, 0xE1, 0x05, 0x00, 0x80, 0x82, 0x83, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // The CC length field says 23 bytes - parsing should use exactly that.
        assert_eq!(&cc_file[..23], &NTAG424_DEFAULT_CC);

        let cc = CapabilityContainer::from_bytes(&cc_file[..23]).unwrap();
        assert_eq!(cc, CapabilityContainer::default());
        assert_eq!(*cc.to_bytes(), NTAG424_DEFAULT_CC);
    }
}
