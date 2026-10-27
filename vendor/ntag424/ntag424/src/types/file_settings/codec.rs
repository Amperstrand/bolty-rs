// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::types::{KeyNumber, file::File};

use super::access::{Access, AccessRights, CommMode, CtrRetAccess, FileType};
use super::error::{FileSettingsError, NibbleSlot, ReservedByte};
use super::sdm::{
    EncFileData, EncLength, EncryptedContent, FileRead, MacWindow, Offset, PiccData, PlainMirror,
    ReadCtrFeatures, ReadCtrMirror, Sdm,
};

/// File settings as returned by
/// [`AuthenticatedSession::get_file_settings`](`crate::AuthenticatedSession::get_file_settings`).
///
/// NT4H2421Gx §10.7.2, Table 73.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettingsView {
    /// File type identifier.
    pub file_type: FileType,
    /// 24-bit file size.
    pub file_size: u32,
    /// Communication mode (how data is protected on the wire).
    ///
    /// The mode passed to [`AuthenticatedSession::read_file_with_mode`](crate::AuthenticatedSession::read_file_with_mode)
    /// and [`AuthenticatedSession::write_file_with_mode`](crate::AuthenticatedSession::write_file_with_mode)
    /// must match this.
    pub comm_mode: CommMode,
    /// Access rights for the file.
    pub access_rights: AccessRights,
    /// Optional Secure Dynamic Messaging (SDM) settings, if SDM is enabled for the file.
    pub sdm: Option<Sdm>,
}

impl FileSettingsView {
    /// Decode a raw `GetFileSettings` response payload.
    ///
    /// The payload is the data after the secure-messaging frame has been
    /// stripped and before the `SW1SW2` status word.
    pub fn decode(buf: &[u8]) -> Result<Self, FileSettingsError> {
        let mut r = Cursor::new(buf);
        let file_type = FileType::from_byte(r.u8()?)?;
        let file_option = r.u8()?;
        let access_rights = AccessRights::from_le_bytes(r.array::<2>()?)?;
        let file_size = r.u24_le()?;

        // bits 7 and 5..2 of FileOption are RFU; bits 1..0 = CommMode, bit 6 = SDM enable.
        if file_option & 0b1011_1100 != 0 {
            return Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::FileOption,
                mask: file_option & 0b1011_1100,
            });
        }

        let sdm = if file_option & (1 << 6) != 0 {
            let sdm_options = r.u8()?;
            let ar_bytes = r.array::<2>()?;

            // bits 2..1 of SDMOptions must be 0; bit 0 must be 1 (ASCII mode).
            if sdm_options & 0b111 != 0b001 {
                return Err(FileSettingsError::ReservedBitSet {
                    byte: ReservedByte::SdmOptions,
                    mask: sdm_options & 0b111,
                });
            }

            // high nibble of SDMAccessRights byte[0] must be 0xF
            if ar_bytes[0] & 0xF0 != 0xF0 {
                return Err(FileSettingsError::ReservedBitSet {
                    byte: ReservedByte::SdmAccessRights0,
                    mask: 0xF0,
                });
            }

            let uid_mirror = sdm_options & (1 << 7) != 0;
            let read_ctr_mirror = sdm_options & (1 << 6) != 0;
            let read_ctr_limit_enabled = sdm_options & (1 << 5) != 0;
            let enc_file_data = sdm_options & (1 << 4) != 0;
            let tt_status_mirror = sdm_options & (1 << 3) != 0;

            let v = u16::from_le_bytes(ar_bytes);
            let picc_meta_nibble = ((v >> 12) & 0xF) as u8;
            let file_read_nibble = ((v >> 8) & 0xF) as u8;
            let ctr_ret_nibble = (v & 0xF) as u8;

            let meta_plain = picc_meta_nibble == 0xE;
            let meta_enc = picc_meta_nibble <= 0x4;
            let picc_meta_key = if meta_enc {
                Some(key_from_nibble(picc_meta_nibble, NibbleSlot::SdmMetaRead)?)
            } else {
                None
            };

            let file_read_key = match file_read_nibble {
                0x0..=0x4 => Some(key_from_nibble(file_read_nibble, NibbleSlot::SdmFileRead)?),
                0xF => None,
                v => {
                    return Err(FileSettingsError::InvalidAccessNibble {
                        slot: NibbleSlot::SdmFileRead,
                        value: v,
                    });
                }
            };

            let ctr_ret = CtrRetAccess::from_nibble(ctr_ret_nibble)?;

            // SDMCtrRet must be NoAccess (0xF) when SDMReadCtr is not mirrored.
            if !read_ctr_mirror && !matches!(ctr_ret, CtrRetAccess::NoAccess) {
                return Err(FileSettingsError::InvalidSdmFlags);
            }

            // Read offsets in wire order
            let uid_offset = if uid_mirror && meta_plain {
                Some(Offset(r.u24_le()?))
            } else {
                None
            };
            let ctr_offset = if read_ctr_mirror && meta_plain {
                Some(r.u24_le()?)
            } else {
                None
            };
            let picc_enc_offset = if meta_enc {
                Some(Offset(r.u24_le()?))
            } else {
                None
            };
            let tt_offset = if tt_status_mirror {
                Some(Offset(r.u24_le()?))
            } else {
                None
            };
            let mac_input_raw = if file_read_key.is_some() {
                Some(r.u24_le()?)
            } else {
                None
            };
            let enc_range = if file_read_key.is_some() && enc_file_data {
                let start = r.u24_le()?;
                let len = r.u24_le()?;
                let el = EncLength::new(len)?;
                Some((Offset(start), el))
            } else {
                None
            };
            let mac_raw = if file_read_key.is_some() {
                Some(r.u24_le()?)
            } else {
                None
            };

            // read_ctr_limit requires read_ctr_mirror
            let ctr_limit = if read_ctr_limit_enabled {
                if !read_ctr_mirror {
                    return Err(FileSettingsError::InvalidSdmFlags);
                }
                let v = r.u24_le()?;
                (v != 0x00FF_FFFF).then_some(v)
            } else {
                None
            };

            // Build ReadCtrFeatures when RCtr is mirrored
            let rctr_features = ReadCtrFeatures {
                limit: ctr_limit,
                ret_access: ctr_ret,
            };

            // Build PiccData
            let picc_data = if meta_plain {
                match (uid_offset, ctr_offset) {
                    (Some(uid), Some(ctr)) => PiccData::Plain(PlainMirror::Both {
                        uid,
                        read_ctr: ReadCtrMirror {
                            offset: Offset(ctr),
                            features: rctr_features,
                        },
                    }),
                    (Some(uid), None) => PiccData::Plain(PlainMirror::Uid { uid }),
                    (None, Some(ctr)) => PiccData::Plain(PlainMirror::RCtr {
                        read_ctr: ReadCtrMirror {
                            offset: Offset(ctr),
                            features: rctr_features,
                        },
                    }),
                    (None, None) => return Err(FileSettingsError::InvalidSdmFlags),
                }
            } else if let Some(key) = picc_meta_key {
                let offset = picc_enc_offset.ok_or(FileSettingsError::InvalidSdmFlags)?;
                let content = match (uid_mirror, read_ctr_mirror) {
                    (true, true) => EncryptedContent::Both(rctr_features),
                    (true, false) => EncryptedContent::Uid,
                    (false, true) => EncryptedContent::RCtr(rctr_features),
                    (false, false) => return Err(FileSettingsError::InvalidSdmFlags),
                };
                PiccData::Encrypted {
                    key,
                    offset,
                    content,
                }
            } else {
                // SDMMetaRead == 0xF: no PICCData
                if picc_meta_nibble != 0xF {
                    return Err(FileSettingsError::InvalidAccessNibble {
                        slot: NibbleSlot::SdmMetaRead,
                        value: picc_meta_nibble,
                    });
                }
                PiccData::None
            };

            // Build FileRead
            let file_read = match (file_read_key, mac_input_raw, mac_raw) {
                (Some(key), Some(mac_input_v), Some(mac_v)) => {
                    let window = MacWindow {
                        input: Offset(mac_input_v),
                        mac: Offset(mac_v),
                    };
                    if let Some((enc_start, enc_len)) = enc_range {
                        Some(FileRead::MacAndEnc {
                            key,
                            window,
                            enc: EncFileData {
                                start: enc_start,
                                length: enc_len,
                            },
                        })
                    } else {
                        Some(FileRead::MacOnly { key, window })
                    }
                }
                (None, None, None) => None,
                _ => return Err(FileSettingsError::InvalidSdmFlags),
            };

            let sdm = Sdm::try_new_from_wire(picc_data, file_read, tt_offset)?;
            Some(sdm)
        } else {
            None
        };

        let rest = r.remaining();
        if rest != 0 {
            return Err(FileSettingsError::TrailingBytes(rest));
        }

        Ok(Self {
            file_type,
            file_size,
            comm_mode: CommMode::from_bits(file_option),
            access_rights,
            sdm,
        })
    }

    /// Return the factory (delivery) file settings for the given file.
    ///
    /// NT4H2421Gx §8.2.3, Table 8 (access rights) and Table 13 (communication
    /// mode). SDM is disabled on all files at delivery.
    pub fn factory(file: File) -> Self {
        match file {
            File::CapabilityContainer => Self {
                file_type: FileType::StandardData,
                comm_mode: CommMode::Plain,
                file_size: file.size(),
                access_rights: AccessRights {
                    read: Access::Free,
                    write: Access::Key(KeyNumber::Key0),
                    read_write: Access::Key(KeyNumber::Key0),
                    change: Access::Key(KeyNumber::Key0),
                },
                sdm: None,
            },
            File::Ndef => Self {
                file_type: FileType::StandardData,
                comm_mode: CommMode::Plain,
                file_size: file.size(),
                access_rights: AccessRights {
                    read: Access::Free,
                    write: Access::Free,
                    read_write: Access::Free,
                    change: Access::Key(KeyNumber::Key0),
                },
                sdm: None,
            },
            File::Proprietary => Self {
                file_type: FileType::StandardData,
                comm_mode: CommMode::Full,
                file_size: file.size(),
                access_rights: AccessRights {
                    read: Access::Key(KeyNumber::Key2),
                    write: Access::Key(KeyNumber::Key3),
                    read_write: Access::Key(KeyNumber::Key3),
                    change: Access::Key(KeyNumber::Key0),
                },
                sdm: None,
            },
        }
    }

    /// Convert to a [`FileSettingsUpdate`] suitable for
    /// [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`).
    ///
    /// This preserves the current communication mode, access rights, and SDM
    /// settings, making it the safest starting point for a read-modify-write
    /// update flow:
    ///
    /// 1. Call [`AuthenticatedSession::get_file_settings`](`crate::AuthenticatedSession::get_file_settings`)
    /// 2. Convert the returned [`FileSettingsView`] with [`Self::into_update`]
    /// 3. Modify the resulting update
    ///
    /// `ChangeFileSettings` overwrites all mutable file-settings fields in one
    /// shot, so starting from [`FileSettingsUpdate::new`] is only appropriate
    /// when you intend to set the complete communication-mode and access-rights
    /// configuration yourself.
    pub fn into_update(self) -> FileSettingsUpdate {
        let patch = FileSettingsUpdate::new(self.comm_mode, self.access_rights);
        match self.sdm {
            Some(sdm) => patch.with_sdm(sdm),
            None => patch,
        }
    }
}

/// Builder for the file settings update payload passed to
/// [`AuthenticatedSession::change_file_settings`](`crate::AuthenticatedSession::change_file_settings`).
///
/// `FileType` and file size are omitted — they cannot be changed.
///
/// NT4H2421Gx §10.7.1, Table 69.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettingsUpdate {
    comm_mode: CommMode,
    access_rights: AccessRights,
    sdm: Option<Sdm>,
}

impl FileSettingsUpdate {
    /// Create a new update with the given communication mode and access rights,
    /// with SDM disabled.
    ///
    /// This is a full replacement for the mutable `ChangeFileSettings` payload:
    /// the provided communication mode, access rights, and any later SDM choice
    /// will overwrite the tag's current values.
    ///
    /// If you only want to adjust one aspect of the current settings (for
    /// example enabling or changing SDM), first read the current settings with
    /// [`AuthenticatedSession::get_file_settings`](`crate::AuthenticatedSession::get_file_settings`),
    /// convert them with [`FileSettingsView::into_update`], then modify that
    /// update. Starting from `new` is easiest to get wrong because omitted
    /// values are not preserved from the tag.
    pub fn new(comm_mode: CommMode, access_rights: AccessRights) -> Self {
        Self {
            comm_mode,
            access_rights,
            sdm: None,
        }
    }

    /// Enable Secure Dynamic Messaging with the given configuration.
    pub fn with_sdm(mut self, sdm: Sdm) -> Self {
        self.sdm = Some(sdm);
        self
    }
}

/// Maximum encoded file settings patch length in bytes.
///
/// `FileOption (1) + AccessRights (2) + SDMOptions (1) + SDMAccessRights (2) + 9 × 3-byte offset fields`.
pub const MAX_CHANGE_FILE_SETTINGS_LEN: usize = 1 + 2 + 1 + 2 + 9 * 3;

impl FileSettingsUpdate {
    /// Encode into the data payload of `ChangeFileSettings`.
    ///
    /// The leading `FileNo` byte is **not** written.
    /// Returns the number of bytes written (at most [`MAX_CHANGE_FILE_SETTINGS_LEN`]).
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, FileSettingsError> {
        let mut w = WCursor::new(buf);

        let mut file_option = self.comm_mode.to_bits();
        if self.sdm.is_some() {
            file_option |= 1 << 6;
        }
        w.u8(file_option)?;
        w.array(&self.access_rights.to_le_bytes())?;

        if let Some(sdm) = &self.sdm {
            let mut sdm_options = 0u8;
            if sdm.picc_data().includes_uid() {
                sdm_options |= 1 << 7;
            }
            if sdm.picc_data().includes_rctr() {
                sdm_options |= 1 << 6;
            }
            if sdm.picc_data().read_ctr_limit().is_some() {
                sdm_options |= 1 << 5;
            }
            if matches!(sdm.file_read(), Some(FileRead::MacAndEnc { .. })) {
                sdm_options |= 1 << 4;
            }
            if sdm.tamper_status().is_some() {
                sdm_options |= 1 << 3;
            }
            sdm_options |= 1; // ASCII always set
            w.u8(sdm_options)?;

            let picc_nibble = match sdm.picc_data() {
                PiccData::None => 0xF,
                PiccData::Plain(_) => 0xE,
                PiccData::Encrypted { key, .. } => key.as_byte(),
            };
            let file_read_nibble = match sdm.file_read() {
                None => 0xF,
                Some(ref fr) => fr.key().as_byte(),
            };
            let ctr_ret_nibble = sdm.picc_data().ctr_ret().to_nibble();
            let ar_word = (u16::from(picc_nibble) << 12)
                | (u16::from(file_read_nibble) << 8)
                | (0xFu16 << 4)
                | u16::from(ctr_ret_nibble);
            w.array(&ar_word.to_le_bytes())?;

            // Offsets in wire order
            match sdm.picc_data() {
                PiccData::None => {}
                PiccData::Plain(PlainMirror::Uid { uid }) => {
                    w.u24_le(uid.0)?;
                }
                PiccData::Plain(PlainMirror::RCtr { read_ctr }) => {
                    w.u24_le(read_ctr.offset.0)?;
                }
                PiccData::Plain(PlainMirror::Both { uid, read_ctr }) => {
                    w.u24_le(uid.0)?;
                    w.u24_le(read_ctr.offset.0)?;
                }
                PiccData::Encrypted { offset, .. } => {
                    w.u24_le(offset.0)?;
                }
            }
            if let Some(tt) = sdm.tamper_status() {
                w.u24_le(tt.0)?;
            }
            if let Some(fr) = sdm.file_read() {
                w.u24_le(fr.window().input.0)?;
                if let Some(enc) = fr.enc() {
                    w.u24_le(enc.start.0)?;
                    w.u24_le(enc.length.0)?;
                }
                w.u24_le(fr.window().mac.0)?;
            }
            if let Some(limit) = sdm.picc_data().read_ctr_limit() {
                w.u24_le(limit)?;
            }
        }

        Ok(w.pos())
    }
}

fn key_from_nibble(n: u8, slot: NibbleSlot) -> Result<KeyNumber, FileSettingsError> {
    Ok(match n {
        0x0 => KeyNumber::Key0,
        0x1 => KeyNumber::Key1,
        0x2 => KeyNumber::Key2,
        0x3 => KeyNumber::Key3,
        0x4 => KeyNumber::Key4,
        v => {
            return Err(FileSettingsError::InvalidAccessNibble { slot, value: v });
        }
    })
}

// (No `FileType::as_byte` needed: encoding `ChangeFileSettings` does not emit
// FileType, and there is currently only one valid value.)

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<(), FileSettingsError> {
        if self.pos + n > self.buf.len() {
            Err(FileSettingsError::BufferTooShort {
                needed: self.pos + n,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8, FileSettingsError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], FileSettingsError> {
        self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }
    fn u24_le(&mut self) -> Result<u32, FileSettingsError> {
        let b = self.array::<3>()?;
        Ok(u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16))
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

struct WCursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> WCursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<(), FileSettingsError> {
        if self.pos + n > self.buf.len() {
            Err(FileSettingsError::BufferTooShort {
                needed: self.pos + n,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self, v: u8) -> Result<(), FileSettingsError> {
        self.need(1)?;
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }
    fn array<const N: usize>(&mut self, src: &[u8; N]) -> Result<(), FileSettingsError> {
        self.need(N)?;
        self.buf[self.pos..self.pos + N].copy_from_slice(src);
        self.pos += N;
        Ok(())
    }
    fn u24_le(&mut self, v: u32) -> Result<(), FileSettingsError> {
        if v > 0x00FF_FFFF {
            return Err(FileSettingsError::OffsetOutOfRange(v));
        }
        self.array(&[
            (v & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            ((v >> 16) & 0xFF) as u8,
        ])
    }
    fn pos(&self) -> usize {
        self.pos
    }
}
