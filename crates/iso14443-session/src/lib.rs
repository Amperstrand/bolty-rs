//! Borrow-free ISO 14443-4 PCD session state, built entirely on the PUBLIC
//! upstream [`iso14443`] API — no fork required.
//!
//! Upstream's `Pcd` takes `&'t mut T` for the whole session lifetime, which
//! is awkward when the transceiver is owned elsewhere (bolty's MFRC522
//! frontend borrows it per-call). This crate holds the protocol state
//! (`ProtocolHandler`, CRC strategy, frame-size bounds, base FWT) separately
//! and drives the transceiver explicitly per exchange.
//!
//! Deltas over upstream's own `Pcd` loop, each load-bearing:
//! - **S(WTX) timeout extension** (ISO 14443-4 §7.5.7): when the card asks
//!   for more time, the transceiver timeout is extended to WTXM × FWT for
//!   the echo and restored after — via the [`TimeoutExt`] hook. NTAG424 DNA
//!   needs this for MAC / key-diversification work.
//! - **Rule-5-correct chain recovery** (§7.5.5): during receive-chain
//!   recovery the SAME R(ACK) is re-sent — the block number was already
//!   toggled, so a freshly built R(ACK) carries the wrong BN and chains get
//!   duplicated data (observed on NTAG424 DNA; upstream's `Pcd` still
//!   rebuilds).
//!
//! FSD enforcement follows upstream SFT-7607: frames longer than the
//! RATS-announced FSD are refused before parsing or accumulation.

// no_std for firmware consumers (apps/bolty-stm32, #111); host test builds
// keep the std prelude for the mpsc-based exchange tests below.
#![cfg_attr(not(test), no_std)]
#[cfg(not(test))]
#[macro_use]
extern crate alloc;

use iso14443::type_a::Frame;
use iso14443::type_a::{
    vec::{ChainVec, FrameVec},
    Action, Ats, Block, BlockType, Cid, Fsdi, Limit, PcdError, PcdTransceiver, ProtocolHandler,
    RatsParam, Role, SBlockSubtype, TypeAError,
};

/// CRC_A over `data` (ISO 14443-3A §6.1.6). Reimplemented locally because
/// upstream keeps `crc` crate-private; verified against the same test
/// vectors in the tests below.
fn crc_a(data: &[u8]) -> (u8, u8) {
    const POLY: u16 = 0x8408;
    let mut crc: u16 = 0x6363;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if (crc & 0x0001) != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    ((crc & 0x00FF) as u8, (crc >> 8) as u8)
}

fn append_crc_a(data: &[u8]) -> Result<FrameVec, TypeAError> {
    let mut out = FrameVec::new();
    out.extend_from_slice(data);
    let (c1, c2) = crc_a(data);
    out.push(c1);
    out.push(c2);
    Ok(out)
}

const MAX_RETRIES: u8 = 2;

/// Optional transceiver hook: extend the receive timeout during S(WTX)
/// exchanges. The default is a no-op returning `Err(())` (WTX echo still
/// happens; only the timeout extension is skipped). Hardware front-ends
/// with a fixed FWT timer override this.
pub trait TimeoutExt {
    // Deliberate `()`: the optional hook carries no diagnostics — callers only test is_ok().
    #[allow(clippy::result_unit_err)]
    fn try_set_timeout_ms(&mut self, _ms: u32) -> Result<(), ()> {
        Err(())
    }
}

/// Borrow-free protocol state for one activated PICC.
#[derive(Debug)]
pub struct PcdSession {
    hw_crc: bool,
    /// Maximum frame size the PICC accepts (from ATS FSCI).
    fsc: usize,
    /// Maximum frame size we told the PICC we accept (from RATS FSDI).
    fsd: usize,
    handler: ProtocolHandler,
    /// Base frame waiting time (FWT) in ms; S(WTX) requests extend the
    /// transceiver timeout to WTXM × FWT (ISO 14443-4 §7.5.7).
    base_fwt_ms: u32,
}

impl PcdSession {
    /// Full setup over a caller-owned transceiver: probe hardware CRC, send
    /// RATS, parse the ATS, and return the borrow-free session state.
    pub fn from_connect<T: PcdTransceiver>(
        t: &mut T,
        fsdi: Fsdi,
        cid: Cid,
    ) -> Result<(Self, Ats), PcdError<T::Error>> {
        let hw_crc = t.try_enable_hw_crc().is_ok();

        let rats = RatsParam::new(fsdi, cid);
        let rats_byte = u8::from(&rats);
        let data = if hw_crc {
            vec![0xe0, rats_byte]
        } else {
            append_crc_a(&[0xe0, rats_byte])?
        };

        let resp = t
            .transceive(&Frame::Standard(data))
            .map_err(PcdError::PcdTransceiver)?;

        let ats = if hw_crc {
            Ats::from_crc_verified(resp.as_slice())?
        } else {
            Ats::try_from(resp.as_slice())?
        };

        Ok((
            Self {
                hw_crc,
                fsc: ats.format.fsci.fsc(),
                fsd: fsdi.fsd(),
                handler: ProtocolHandler::new(Role::Pcd, Some(cid)),
                base_fwt_ms: 0,
            },
            ats,
        ))
    }

    /// Manual construction for callers that already handled RATS/ATS
    /// externally. The FSD ceiling defaults to the ATS's FSCI — callers
    /// that announced a smaller FSD should take the `from_connect` path.
    pub fn from_ats(ats: &Ats, cid: Option<Cid>, hw_crc: bool) -> Self {
        Self {
            hw_crc,
            fsc: ats.format.fsci.fsc(),
            fsd: ats.format.fsci.fsc(),
            handler: ProtocolHandler::new(Role::Pcd, cid),
            base_fwt_ms: 0,
        }
    }

    pub fn hw_crc(&self) -> bool {
        self.hw_crc
    }

    pub fn set_fsc(&mut self, fsc: usize) {
        self.fsc = fsc;
    }

    pub fn set_base_fwt_ms(&mut self, ms: u32) {
        self.base_fwt_ms = ms;
    }

    /// Exchange an APDU with the PICC over a caller-owned transceiver:
    /// PCD-side chaining, PICC-side chaining, WTX handling, §7.5.5
    /// recovery. Session state survives across calls.
    pub fn exchange<T: PcdTransceiver + TimeoutExt>(
        &mut self,
        t: &mut T,
        apdu: &[u8],
    ) -> Result<ChainVec, PcdError<T::Error>> {
        self.handler.begin_exchange();

        let cid_len = if self.handler.build_iblock(&[], false)?.cid.is_some() {
            1
        } else {
            0
        };
        let overhead = 1 + cid_len + 2;
        let max_inf = self.fsc.saturating_sub(overhead);
        if max_inf == 0 {
            return Err(PcdError::Protocol(TypeAError::Other));
        }

        let mut offset = 0;
        let mut last_resp: Option<Block> = None;

        // --- PCD-side chaining (send APDU) ---
        while offset < apdu.len() {
            let end = core::cmp::min(offset + max_inf, apdu.len());
            let chaining = end < apdu.len();
            let iblock = self.handler.build_iblock(&apdu[offset..end], chaining)?;

            let resp = self.transceive_block(t, &iblock)?;

            if chaining {
                match self.handler.process_received(resp)? {
                    Action::ChainingAck => offset = end,
                    Action::ChainingRetransmit => continue,
                    _ => return Err(PcdError::Protocol(TypeAError::Other)),
                }
            } else {
                // The PICC answers the last chunk with an I-Block carrying
                // this same block number; Rule B toggles when that block is
                // taken in, not before it arrives.
                last_resp = Some(resp);
                offset = end;
            }
        }

        // --- PICC-side chaining (receive response) ---
        let first = last_resp.ok_or(PcdError::Protocol(TypeAError::Other))?;
        self.collect_response(t, first)
    }

    /// Send S(DESELECT), wait for the echo. Retries once per Rule 8.
    pub fn deselect<T: PcdTransceiver + TimeoutExt>(
        &mut self,
        t: &mut T,
    ) -> Result<(), PcdError<T::Error>> {
        let deselect = self.handler.build_sblock(SBlockSubtype::Deselect)?;

        match self.transceive_block(t, &deselect) {
            Ok(ref resp)
                if resp.block_type() == BlockType::SBlock
                    && resp.pcb.s_subtype == Some(SBlockSubtype::Deselect) =>
            {
                Ok(())
            }
            _ => {
                let resp = self.transceive_block(t, &deselect)?;
                if resp.block_type() == BlockType::SBlock
                    && resp.pcb.s_subtype == Some(SBlockSubtype::Deselect)
                {
                    Ok(())
                } else {
                    Err(PcdError::Protocol(TypeAError::Other))
                }
            }
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    fn collect_response<T: PcdTransceiver + TimeoutExt>(
        &mut self,
        t: &mut T,
        first: Block,
    ) -> Result<ChainVec, PcdError<T::Error>> {
        let mut block = first;

        loop {
            match self.handler.process_received(block)? {
                Action::Complete(data) => return Ok(data),
                Action::Reply(reply) => {
                    // S(WTX): extend the transceiver timeout to WTXM × FWT
                    // around the echo, restore after (§7.5.7).
                    let is_wtx = reply.block_type() == BlockType::SBlock
                        && reply.pcb.s_subtype == Some(SBlockSubtype::Wtx);
                    if is_wtx && self.base_fwt_ms > 0 {
                        let wtxm = reply.payload.as_slice().first().copied().unwrap_or(1) as u32;
                        let extended = (wtxm * self.base_fwt_ms).max(self.base_fwt_ms);
                        let _ = t.try_set_timeout_ms(extended);
                        block = self.transceive_with_recovery(t, &reply, true)?;
                        let _ = t.try_set_timeout_ms(self.base_fwt_ms);
                    } else {
                        block = self.transceive_with_recovery(t, &reply, true)?;
                    }
                }
                _ => return Err(PcdError::Protocol(TypeAError::Other)),
            }
        }
    }

    /// §7.5.5 recovery. Rule 5 (receive-chain): re-send the SAME R(ACK) —
    /// the block number was already toggled by `process_received`, so a
    /// freshly built R(ACK) carries the wrong BN. Rule 4 (send-chain):
    /// R(NAK).
    fn transceive_with_recovery<T: PcdTransceiver + TimeoutExt>(
        &mut self,
        t: &mut T,
        block: &Block,
        receiving_chain: bool,
    ) -> Result<Block, PcdError<T::Error>> {
        match self.transceive_block(t, block) {
            Ok(resp) => Ok(resp),
            Err(_) => {
                let mut retries = 0;
                loop {
                    if retries >= MAX_RETRIES {
                        return Err(PcdError::Protocol(TypeAError::Other));
                    }
                    retries += 1;

                    if receiving_chain {
                        match self.transceive_block(t, block) {
                            Ok(resp) => return Ok(resp),
                            Err(_) => continue,
                        }
                    } else {
                        let recovery = self.handler.build_rnak()?;
                        match self.transceive_block(t, &recovery) {
                            Ok(resp) => return Ok(resp),
                            Err(_) => continue,
                        }
                    }
                }
            }
        }
    }

    fn transceive_block<T: PcdTransceiver>(
        &mut self,
        t: &mut T,
        block: &Block,
    ) -> Result<Block, PcdError<T::Error>> {
        let data = block.to_bytes_without_crc()?;
        let frame = if self.hw_crc {
            Frame::Standard(data)
        } else {
            Frame::Standard(append_crc_a(&data)?)
        };

        let resp = t.transceive(&frame).map_err(PcdError::PcdTransceiver)?;

        // SFT-7607: refuse an over-FSD frame before parsing or accumulation.
        let effective = resp.len() + if self.hw_crc { 2 } else { 0 };
        if effective > self.fsd {
            return Err(PcdError::Protocol(Limit::FrameSize.into()));
        }

        if self.hw_crc {
            Ok(Block::from_crc_verified(resp.as_slice())?)
        } else {
            Ok(Block::try_from(resp.as_slice())?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ISO 14443-3A §6.1.6 example + the classic "00" vector (matches
    // upstream crc.rs tests byte-for-byte).
    #[test]
    fn crc_a_matches_iso_vectors() {
        // Upstream crc.rs ex1/ex2, byte-for-byte.
        assert_eq!(crc_a(&[0x00, 0x00]), (0xA0, 0x1E));
        assert_eq!(crc_a(&[0x12, 0x34]), (0x26, 0xCF));
    }

    #[test]
    fn append_crc_appends_two_bytes() {
        let out = append_crc_a(&[0xe0, 0x51]).unwrap();
        assert_eq!(out.len(), 4);
        let (c1, c2) = crc_a(&[0xe0, 0x51]);
        assert_eq!(&out[2..], &[c1, c2]);
    }
}

#[cfg(test)]
mod exchange_tests {
    use super::*;
    use iso14443::type_a::{Block, Frame, PcdTransceiver};
    use std::sync::mpsc::{channel, Receiver, Sender};

    #[derive(Debug)]
    struct ChanErr;

    // Minimal scripted transceiver: pops canned responses in order.
    struct Scripted {
        responses: Vec<Vec<u8>>,
        idx: usize,
        sent: Vec<Vec<u8>>,
    }

    impl PcdTransceiver for Scripted {
        type Error = ChanErr;
        fn transceive(&mut self, frame: &Frame) -> Result<Vec<u8>, ChanErr> {
            self.sent.push(frame.data().to_vec());
            if self.idx < self.responses.len() {
                let r = self.responses[self.idx].clone();
                self.idx += 1;
                Ok(r)
            } else {
                Err(ChanErr)
            }
        }
        fn try_enable_hw_crc(&mut self) -> Result<(), ChanErr> {
            Err(ChanErr) // software CRC path
        }
    }

    impl TimeoutExt for Scripted {
        fn try_set_timeout_ms(&mut self, _ms: u32) -> Result<(), ()> {
            Ok(())
        }
    }

    fn wrap(iblock_body: &[u8]) -> Vec<u8> {
        // add a plausible PCB + the body; CRC is appended by the session
        let mut v = vec![0x02u8]; // I-block, no CID, BN=0, no chaining
        v.extend_from_slice(iblock_body);
        let (c1, c2) = crc_a(&v);
        v.push(c1);
        v.push(c2);
        v
    }

    #[test]
    fn exchange_single_iblock_roundtrip() {
        // ATS FSCI=8 (FSC 256) — generous
        let ats_bytes = [0x07u8, 0x72, 0xF0, 0x40, 0x91, 0x00, 0x00];
        let ats = Ats::try_from(append_crc_a(&ats_bytes).unwrap().as_slice()).unwrap();
        let mut session = PcdSession::from_ats(&ats, None, false);

        let payload = b"hello".to_vec();
        let resp_block = {
            let mut v = vec![0x02u8];
            v.extend_from_slice(&payload);
            let (c1, c2) = crc_a(&v);
            v.push(c1);
            v.push(c2);
            v
        };
        let mut t = Scripted {
            responses: vec![resp_block],
            idx: 0,
            sent: vec![],
        };
        let out = session.exchange(&mut t, b"req").unwrap();
        assert_eq!(out.as_slice(), &payload[..]);
    }
}
