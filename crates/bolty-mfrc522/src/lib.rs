//! MFRC522 NFC frontend transport for NTAG424 card communication.
//!
//! Implements the `ntag424::Transport` trait over I²C-connected MFRC522
//! hardware, handling ISO/IEC 14443-4 Type A activation, ISO-DEP frame
//! transceive with hardware CRC, and APDU-level exchange with the card.
//!
//! `#![no_std]`-compatible (uses `alloc`).
//!
//! Key types: `Mfrc522Transceiver` (re-exported from `mfrc522-pcd`),
//! `Mfrc522Transport`, `Error`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};

use embedded_hal::delay::DelayNs;
use embedded_hal::i2c::I2c;
use iso14443::type_a::{Ats, Cid, Fsdi, PcdError, activation};
use iso14443_session::PcdSession;
use mfrc522::Error as Mfrc522Error;
use ntag424::{Response, Transport};

// Re-export the PCD-layer types from mfrc522-pcd so consumers of bolty-mfrc522
// see the same public API as before.
pub use mfrc522_pcd::{DEFAULT_I2C_ADDRESS, FnDelay, Mfrc522Transceiver, NoDelay};

/// Marginal coupling makes a single REQA→RATS sequence flaky (~50% on the
/// bench, ccid-firmware-rs 2026-10-09 against a J3R180):
/// [`Mfrc522Transport::activate_with_delays`] retries the activation up to
/// this many times with a fresh frontend reset between attempts (~50% →
/// 20/20 on their bench).
pub const ACTIVATION_ATTEMPTS: usize = 4;

/// Settle time between the antenna/frontend reset and the first WUPA, and
/// again between retry attempts — a card's charge pump needs it after a
/// field cycle (JavaCards need more than DESFire).
pub const ACTIVATION_SETTLE_MS: u32 = 15;

/// Whether an [`Error`] is worth retrying: radio/I2C/protocol classes are
/// transient (marginal coupling, wedged ISO-14443-4 state), while
/// `UnsupportedTag` and `InvalidUidLength` are deterministic card
/// properties — retrying those just burns 4× the poll budget.
pub fn is_retryable_activation_error<E>(e: &Error<E>) -> bool {
    !matches!(
        e,
        Error::UnsupportedTag | Error::InvalidUidLength(_) | Error::InvalidCid
    )
}

/// NFC transport over MFRC522, borrowing the transceiver for the card session lifetime.
///
/// The transceiver is NOT consumed — `activate()` takes `&mut`, so the caller
/// retains ownership and can re-activate after the card is released.
pub struct Mfrc522Transport<'a, I2C: I2c> {
    transceiver: &'a mut Mfrc522Transceiver<I2C>,
    session: PcdSession,
    uid: Vec<u8>,
}

impl<'a, I2C: I2c> Mfrc522Transport<'a, I2C> {
    pub fn activate(
        transceiver: &'a mut Mfrc522Transceiver<I2C>,
    ) -> Result<Self, Error<I2C::Error>> {
        transceiver
            .prepare_for_activation()
            .map_err(Error::Mfrc522)?;
        Self::activate_after_prepare(transceiver)
    }

    /// Activation with the bench-proven reliability ladder: up to
    /// [`ACTIVATION_ATTEMPTS`] rounds of (antenna cycle with field-off
    /// dwell → settle → WUPA), then one full activation. The retry
    /// budget targets the flaky part — marginal coupling loses REQA/WUPA,
    /// not the RATS that follows an answered WUPA.
    pub fn activate_with_delays<D: DelayNs>(
        transceiver: &'a mut Mfrc522Transceiver<I2C>,
        delay: &mut D,
    ) -> Result<Self, Error<I2C::Error>> {
        let mut last_err: Option<Error<I2C::Error>> = None;
        for _attempt in 1..=ACTIVATION_ATTEMPTS {
            if let Err(e) = transceiver.prepare_for_activation_with_delays(delay) {
                last_err = Some(Error::Mfrc522(e));
                continue;
            }
            delay.delay_ms(ACTIVATION_SETTLE_MS);
            match activation::wakeup(transceiver) {
                // ISO 14443-3: a PICC in ACTIVE state does not answer a
                // further WUPA — the answered activation must flow
                // STRAIGHT into RATS/session setup (Codex PR #93 P1);
                // re-entering activate_after_prepare here would issue a
                // second WUPA with no field reset and convert success
                // into CardNotPresent.
                Ok(activation) => return Self::from_activation(transceiver, activation),
                Err(e) => last_err = Some(Error::Activation(e)),
            }
        }
        Err(last_err.unwrap_or(Error::Mfrc522(Mfrc522Error::Timeout)))
    }

    pub fn activate_after_prepare(
        transceiver: &'a mut Mfrc522Transceiver<I2C>,
    ) -> Result<Self, Error<I2C::Error>> {
        let activation = activation::wakeup(transceiver).map_err(Error::Activation)?;
        Self::from_activation(transceiver, activation)
    }

    /// Post-wakeup session setup: the caller supplies a SUCCESSFUL
    /// activation (card ACTIVE) and this runs the SAK/UID checks, RATS,
    /// and ISO-DEP session bring-up — never another WUPA.
    fn from_activation(
        transceiver: &'a mut Mfrc522Transceiver<I2C>,
        activation: activation::Activation,
    ) -> Result<Self, Error<I2C::Error>> {
        if !activation.sak.iso14443_4_compliant {
            return Err(Error::UnsupportedTag);
        }
        validate_uid(activation.uid.as_slice())?;

        let cid = Cid::new(0).ok_or(Error::InvalidCid)?;
        let (_, ats) =
            PcdSession::from_connect(transceiver, Fsdi::Fsd64, cid).map_err(Error::Protocol)?;

        transceiver.enable_hw_crc().map_err(Error::Mfrc522)?;

        let mut session = PcdSession::from_ats(&ats, None, true);
        session.set_fsc(core::cmp::min(ats.format.fsci.fsc(), 64));

        let fwt_ms = frame_wait_time_ms(&ats);
        transceiver.set_timeout_ms(fwt_ms).map_err(Error::Mfrc522)?;
        session.set_base_fwt_ms(fwt_ms);

        Ok(Self {
            transceiver,
            session,
            uid: activation.uid,
        })
    }

    pub fn uid(&self) -> &[u8] {
        self.uid.as_slice()
    }
}

impl<'a, I2C> Transport for Mfrc522Transport<'a, I2C>
where
    I2C: I2c,
    I2C::Error: Debug,
{
    type Error = Error<I2C::Error>;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Self::Data>, Self::Error> {
        let response = self
            .session
            .exchange(self.transceiver, apdu)
            .map_err(Error::Protocol)?;
        split_response(response.as_slice())
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        Ok(self.uid.clone())
    }
}

#[derive(Debug)]
pub enum Error<E> {
    Mfrc522(Mfrc522Error<E>),
    Activation(activation::ActivationError<Mfrc522Error<E>>),
    Protocol(PcdError<Mfrc522Error<E>>),
    InvalidCid,
    InvalidResponseLength(usize),
    InvalidUidLength(usize),
    UnsupportedTag,
}

impl<E: Debug> Display for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<E: Debug> core::error::Error for Error<E> {}

fn validate_uid<E>(uid: &[u8]) -> Result<(), Error<E>> {
    match uid.len() {
        4 | 7 => Ok(()),
        len => Err(Error::InvalidUidLength(len)),
    }
}

/// SAFETY: response.len() >= 2 is checked above, so split = len-2 and
/// split+1 are always valid indices.
#[allow(clippy::indexing_slicing)]
fn split_response<E>(response: &[u8]) -> Result<Response<Vec<u8>>, Error<E>> {
    if response.len() < 2 {
        return Err(Error::InvalidResponseLength(response.len()));
    }

    let split = response.len() - 2;
    Ok(Response {
        data: response[..split].to_vec(),
        sw1: response[split],
        sw2: response[split + 1],
    })
}

#[cfg(feature = "std")]
fn frame_wait_time_ms(ats: &Ats) -> u32 {
    // Upstream's Fwi::fwt() is the spec formula (256*16/fc * 2^FWI); our
    // old .value() arithmetic produced the same numbers via 302us steps.
    let us = ats.tb.fwi.fwt().as_micros() as u32;
    if us == 0 { 5 } else { us / 1000 + 10 }
}

#[cfg(not(feature = "std"))]
fn frame_wait_time_ms(ats: &Ats) -> u32 {
    // no_std: upstream iso14443 gates Fwi::fwt() (Duration) behind "std" and
    // exposes no raw-FWI accessor (Fwi(pub(crate) u8)), so the declared FWT
    // is unreadable through the parsed Ats. Recover TB(1) from the
    // serialized ATS (to_bytes() is public no_std API) and apply the same
    // spec formula locally, so cards declaring FWI != 4 get their real FWT
    // here too. Falls back to the ISO 14443-4 default FWI=4 (14 ms) when
    // TB(1) is absent, matching the std path.
    //
    // Upstream fix proposed in
    // https://github.com/Foundation-Devices/iso14443-rs/pull/8
    // (core::time::Duration needs no std). Once that merges and we re-pin,
    // delete this cfg split and keep only the fwt()-based path above.
    let fwi = fwi_from_ats(ats).unwrap_or(4);
    let us = 302u64 * (1u64 << fwi);
    (us / 1000) as u32 + 10
}

/// FWI as declared in TB(1) of the serialized ATS (high nibble), or None
/// when TB(1) is absent or the ATS is too short to carry one.
#[cfg(any(not(feature = "std"), test))]
fn fwi_from_ats(ats: &Ats) -> Option<u8> {
    let bytes = ats.to_bytes().ok()?;
    let t0 = *bytes.get(1)?;
    let mut i = 2usize;
    if t0 & 0b0001_0000 != 0 {
        i += 1; // TA(1)
    }
    if t0 & 0b0010_0000 == 0 {
        return None; // TB(1) not transmitted -> default FWI
    }
    Some(*bytes.get(i)? >> 4)
}

#[cfg(test)]
mod tests {

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    /// Cross-crate response-split conformance contract (mirrored in
    /// bolty-mfrc522, bolty-pn532 and bolty-pn7160). The hoist was
    /// evaluated 2026-10-20: the only shared dependency is the
    /// rev-pinned ntag424 fork (frozen pending the owner's
    /// feed-vs-retire decision), so the 8-line split stays crate-local
    /// and THESE vectors are the drift guard — change one, change all
    /// three. Natural hoist home if the fork decision lands: a
    /// Response helper on the ntag424 fork itself.
    #[test]
    fn split_response_conformance() {
        // <2 bytes is always InvalidResponseLength(len)
        for short in [&[][..], &[0x6Fu8][..]] {
            match super::split_response::<core::convert::Infallible>(short) {
                Err(Error::InvalidResponseLength(n)) => assert_eq!(n, short.len()),
                Err(other) => panic!("expected InvalidResponseLength, got {other:?}"),
                Ok(_) => panic!("short input must not split"),
            }
        }
        // status-word-only responses
        for (rsp, sw) in [
            (&[0x90u8, 0x00][..], (0x90u8, 0x00u8)),
            (&[0x61, 0x00][..], (0x61, 0x00)),
            (&[0x67, 0x00][..], (0x67, 0x00)),
        ] {
            match super::split_response::<core::convert::Infallible>(rsp) {
                Ok(r) => {
                    assert!(r.data.is_empty());
                    assert_eq!((r.sw1, r.sw2), sw);
                }
                Err(e) => panic!("expected Ok, got {e:?}"),
            }
        }
        // data + status word, incl. SW-looking bytes inside data
        let cases: &[(&[u8], &[u8], u8, u8)] = &[
            (&[0x6F, 0x10, 0x90, 0x00], &[0x6F, 0x10], 0x90, 0x00),
            (&[0x00, 0xFF, 0x67, 0x00], &[0x00, 0xFF], 0x67, 0x00),
            (
                &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x90, 0x00],
                &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
                0x90,
                0x00,
            ),
        ];
        for (rsp, data, sw1, sw2) in cases {
            match super::split_response::<core::convert::Infallible>(rsp) {
                Ok(r) => {
                    assert_eq!(r.data.as_slice(), *data);
                    assert_eq!((r.sw1, r.sw2), (*sw1, *sw2));
                }
                Err(e) => panic!("expected Ok, got {e:?}"),
            }
        }
    }

    #[test]
    fn deterministic_card_errors_are_not_retryable() {
        assert!(!is_retryable_activation_error(&Error::<u8>::UnsupportedTag));
        assert!(!is_retryable_activation_error(
            &Error::<u8>::InvalidUidLength(5)
        ));
        assert!(!is_retryable_activation_error(&Error::<u8>::InvalidCid));
    }

    #[test]
    fn transient_radio_errors_are_retryable() {
        assert!(is_retryable_activation_error(&Error::<u8>::Mfrc522(
            Mfrc522Error::Timeout
        )));
        assert!(is_retryable_activation_error(&Error::<u8>::Mfrc522(
            Mfrc522Error::Nak
        )));
        assert!(is_retryable_activation_error(&Error::<u8>::Protocol(
            PcdError::PcdTransceiver(Mfrc522Error::Timeout)
        )));
    }

    #[test]
    fn ladder_constants_match_bench_proven_values() {
        assert_eq!(ACTIVATION_ATTEMPTS, 4);
        assert_eq!(ACTIVATION_SETTLE_MS, 15);
        assert_eq!(mfrc522_pcd::FIELD_OFF_DWELL_MS, 50);
        assert_eq!(mfrc522_pcd::FIELD_ON_SETTLE_MS, 5);
    }

    #[test]
    fn no_std_fwt_parser_matches_upstream_fwt() {
        for fwi in 0..=14u8 {
            for sfgi in [0u8, 5] {
                let ats = Ats::from_crc_verified(&[0x03, 0x20, (fwi << 4) | sfgi]).unwrap();
                let parsed = fwi_from_ats(&ats);
                assert_eq!(parsed, Some(fwi));
                // The exact expression the no_std path uses must agree with
                // upstream's spec formula (fwt() is available under std).
                let us = 302u64 * (1u64 << parsed.unwrap());
                assert_eq!(us, ats.tb.fwi.fwt().as_micros() as u64);
            }
        }
    }

    // T0 presence bits — ISO 14443-4 §5.2.3; identical in upstream
    // Format::try_from (src/type_a/ats.rs @ 216d1b9) and in proxmark3's
    // ATS decoder (client/src/cmdhf14a.c: ta1 = ats[1] & 0x10, tb1 = ats[1]
    // & 0x20, tc1 = ats[1] & 0x40):
    //   0b0001_0000 = TA(1) present
    //   0b0010_0000 = TB(1) present
    //   0b0100_0000 = TC(1) present
    // Interface bytes always follow T0 in the order TA(1), TB(1), TC(1).
    // TB carries FWI 8 (0x80); markers: TA = 0x5A, TC = 0x03, hist = AA BB.
    #[test]
    fn parser_walks_t0_presence_combinations() {
        let tb = 0x80u8; // FWI 8, SFGI 0
        for (t0, ta, tc) in [
            (0x20u8, None, None),                 // TB only
            (0x30u8, Some(0x5Au8), None),         // TA + TB
            (0x60u8, None, Some(0x03u8)),         // TB + TC (TA absent)
            (0x70u8, Some(0x5Au8), Some(0x03u8)), // TA + TB + TC
            (0x72u8, Some(0x5Au8), Some(0x03u8)), // same, FSCI 2 in low nibble
        ] {
            let mut body = Vec::new();
            body.push(t0);
            if let Some(ta_byte) = ta {
                body.push(ta_byte);
            }
            body.push(tb);
            if let Some(tc_byte) = tc {
                body.push(tc_byte);
            }
            body.extend_from_slice(&[0xAA, 0xBB]); // historical bytes

            let mut with_tl = Vec::with_capacity(body.len() + 1);
            with_tl.push((body.len() + 1) as u8);
            with_tl.extend_from_slice(&body);

            let ats = Ats::from_crc_verified(&with_tl).unwrap();
            // Ground truth of the constructed frame: TB(1) = 0x80 -> FWI 8.
            assert_eq!(fwi_from_ats(&ats), Some(8), "T0 = {t0:#04x}");
            // Oracle: upstream's parsed Fwi must agree (302us * 2^8).
            assert_eq!(ats.tb.fwi.fwt().as_micros() as u64, 302 * (1u64 << 8));
        }
    }

    #[test]
    fn parser_returns_none_whenever_tb_is_absent() {
        for (t0, ta, tc) in [
            (0x00u8, None, None),
            (0x10u8, Some(0x5Au8), None),         // TA only
            (0x40u8, None, Some(0x03u8)),         // TC only
            (0x50u8, Some(0x5Au8), Some(0x03u8)), // TA + TC
        ] {
            let mut body = Vec::new();
            body.push(t0);
            if let Some(ta_byte) = ta {
                body.push(ta_byte);
            }
            if let Some(tc_byte) = tc {
                body.push(tc_byte);
            }
            body.push(0xAA);

            let mut with_tl = Vec::new();
            with_tl.push((body.len() + 1) as u8);
            with_tl.extend_from_slice(&body);

            let ats = Ats::from_crc_verified(&with_tl).unwrap();
            assert_eq!(fwi_from_ats(&ats), None, "T0 = {t0:#04x}");
            // Fallback parity: FWI=4 default must equal the std path (14 ms).
            let ms = (302u64 * (1u64 << fwi_from_ats(&ats).unwrap_or(4)) / 1000) as u32 + 10;
            assert_eq!(ms, 14);
            assert_eq!(ms, frame_wait_time_ms(&ats));
        }

        // The shortest legal ATS (TL = 1, no T0 at all) also falls back.
        let shortest = Ats::from_crc_verified(&[0x01]).unwrap();
        assert_eq!(fwi_from_ats(&shortest), None);
        assert_eq!(frame_wait_time_ms(&shortest), 14);
    }
}
