// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use core::{error::Error, fmt::Debug};

/// A raw APDU-level transport. The implementor handles framing, the
/// NFC layer, USB HID (e.g. ACR1252U), or any other physical channel.
///
/// # Implementing this trait
///
/// ## Connection ownership
///
/// The implementor owns the live reader/card connection and is
/// responsible for establishing it before the first call and tearing
/// it down after the last. [`Session`](crate::Session) borrows the
/// transport mutably for each operation but never opens, closes, or
/// resets it. If the card is removed mid-session, surface the
/// reader's error through [`Self::Error`]; the session is then no
/// longer usable and the caller must drop it.
///
/// The library tracks the *logical* application/EF selection state
/// (NDEF AID, current EF) on the [`Session`](crate::Session) itself,
/// not on the transport. Implementors should not cache or replay
/// `SELECT` APDUs; just forward bytes.
///
/// ## APDU format
///
/// Only ISO 7816-4 *short-form* APDUs are emitted (NT4H2421Gx §8.4):
///
/// - `apdu` is at most `5 + 255 + 1 = 261` bytes (header, 1-byte
///   `Lc`, body, 1-byte `Le`); never extended-length.
/// - All four ISO cases occur. `Le` is included whenever a response
///   is expected (`Le = 0x00` meaning "up to 256 bytes"); case-3
///   commands (e.g. `ISOUpdateBinary`) carry no `Le` byte.
/// - Each call corresponds to exactly one APDU exchange. Multi-frame
///   protocol flows (`ADDITIONAL_FRAME`/`AF` chaining for
///   `ReadData`, `WriteData`, `GetVersion`, the two-leg
///   `AuthenticateEV2*` handshake) are driven by the library across
///   multiple `transmit` calls; the transport must not coalesce or
///   split frames.
///
/// ## Returning a [`Response`]
///
/// `data` must contain the response body **without** the trailing
/// SW1/SW2; those go in the dedicated fields. An empty body is
/// represented by an empty `Self::Data`. Any status word — including
/// non-`9000` codes such as `91AF` (`ADDITIONAL_FRAME`) or `91AE`
/// (`AUTHENTICATION_ERROR`) — must be passed through unchanged: the
/// library parses status words itself and relies on seeing them. Do
/// not translate tag-side errors into `Self::Error`; reserve
/// `Self::Error` for transport/IO failures (reader disconnect,
/// timeout, malformed framing).
///
/// ## `get_uid`
///
/// Must return the UID seen by the reader during ISO/IEC 14443-3
/// anti-collision, as a 4- or 7-byte slice. This is *not* necessarily
/// the tag's permanent UID: a tag in random-ID mode returns a
/// freshly-randomised 4-byte single-size UID (leading byte `0x08`)
/// here, and the permanent UID is only available via the
/// authenticated `GetCardUID` command
/// ([`AuthenticatedSession::get_uid`](crate::AuthenticatedSession::get_uid)).
/// PC/SC readers typically expose this via the `FF CA 00 00 00`
/// pseudo-APDU; see [`ntag424-pcsc`] for a reference implementation.
///
/// ## Concurrency
///
/// The library calls `transmit` and `get_uid` strictly sequentially
/// on a single transport, and both methods take `&mut self`, so
/// implementations need not be `Sync` or re-entrant. A `&mut`
/// transport is threaded through every authenticated operation and
/// command-counter advance, so concurrent use against the same tag
/// would desynchronise the secure channel.
///
/// [`ntag424-pcsc`]: https://crates.io/crates/ntag424-pcsc
pub trait Transport {
    /// Transport/IO error type. Used for reader-level failures (lost
    /// connection, timeout, framing error). Tag-side error responses
    /// must be reported via SW1/SW2 in [`Response`], not through this
    /// type.
    type Error: Error + Debug;

    /// Owned or borrowed byte container for response payloads and
    /// UIDs. Typically `Vec<u8>` on `std` targets or a stack-allocated
    /// `ArrayVec`/`heapless::Vec` on `no_std`.
    type Data: AsRef<[u8]>;

    /// Transmit a single short-form APDU and return the tag's
    /// response.
    ///
    /// `apdu` is a complete ISO 7816-4 short APDU (≤ 261 bytes). The
    /// returned [`Response`] must contain the response body in `data`
    /// (without SW1/SW2) and the trailing status word in `sw1`/`sw2`,
    /// unmodified. See the trait-level "Implementing this trait"
    /// section for full requirements.
    fn transmit(
        &mut self,
        apdu: &[u8],
    ) -> impl Future<Output = Result<Response<Self::Data>, Self::Error>>;

    /// Get the UID of the tag as seen during anti-collision.
    ///
    /// Must return either 4 bytes (single-size UID, e.g. when the tag
    /// is in random-ID mode) or 7 bytes (double-size UID). Other
    /// lengths are rejected by the library. See the trait-level
    /// section for the distinction from the tag's permanent UID.
    fn get_uid(&mut self) -> impl Future<Output = Result<Self::Data, Self::Error>>;
}

/// A response to an APDU command, containing the data and the status words.
///
/// `data` carries the response body only; SW1/SW2 are reported
/// separately in [`Self::sw1`] and [`Self::sw2`].
pub struct Response<D: AsRef<[u8]>> {
    /// Response body, with the trailing SW1/SW2 stripped. May be empty.
    pub data: D,
    /// Status word 1 (SW1) as returned by the tag.
    pub sw1: u8,
    /// Status word 2 (SW2) as returned by the tag.
    pub sw2: u8,
}

impl<D: AsRef<[u8]>> Response<D> {
    /// Get the status code.
    pub fn status(&self) -> u16 {
        (self.sw1 as u16) << 8 | self.sw2 as u16
    }
}
