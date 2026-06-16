// SPDX-FileCopyrightText: \u00a9 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! PCD \u2194 PICC loopback integration tests.
//!
//! Exercises the full ISO/IEC 14443 protocol stack from the `iso14443` crate
//! using in-memory channels between a PCD (reader) and PICC (card emulation).
//! The PICC runs in a separate thread; the PCD runs in the test thread.
//!
//! Tests cover: activation (REQA), RATS/ATS, PPS, short APDU, long APDU with
//! I-Block chaining, DESELECT, and WUPA re-activation.

#![allow(clippy::unwrap_used)]

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use iso14443::type_a::{
    Ats, Cid, Dxi, Frame, Fsci, Fsdi, PcdTransceiver, PiccTransceiver, Ta, Tb, Tc,
    activation::{activate, wakeup},
    pcd::Pcd,
    picc::{Picc, PiccConfig, PiccError, Uid},
};

// ── Channel-based transceivers ──────────────────────────────────────────

#[derive(Debug)]
struct ChannelError;

/// PCD-side transceiver: sends a frame, waits for the PICC response.
struct ChannelPcd {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl PcdTransceiver for ChannelPcd {
    type Error = ChannelError;

    fn transceive(&mut self, frame: &Frame) -> Result<Vec<u8>, ChannelError> {
        let data = frame.data().to_vec();
        self.tx.send(data).map_err(|_| ChannelError)?;
        self.rx.recv().map_err(|_| ChannelError)
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), ChannelError> {
        Err(ChannelError) // no HW CRC in loopback
    }
}

/// PICC-side transceiver: waits for a frame from the PCD, sends response.
struct ChannelPicc {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl PiccTransceiver for ChannelPicc {
    type Error = ChannelError;

    fn receive(&mut self) -> Result<Vec<u8>, ChannelError> {
        self.rx.recv().map_err(|_| ChannelError)
    }

    fn send(&mut self, frame: &Frame) -> Result<(), ChannelError> {
        self.tx
            .send(frame.data().to_vec())
            .map_err(|_| ChannelError)
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), ChannelError> {
        Err(ChannelError)
    }
}

/// Create a linked pair of PCD and PICC channel transceivers.
fn channel_pair() -> (ChannelPcd, ChannelPicc) {
    let (pcd_tx, picc_rx) = mpsc::channel();
    let (picc_tx, pcd_rx) = mpsc::channel();
    (
        ChannelPcd {
            tx: pcd_tx,
            rx: pcd_rx,
        },
        ChannelPicc {
            tx: picc_tx,
            rx: picc_rx,
        },
    )
}

// ── PICC thread helper ──────────────────────────────────────────────────

/// Card UID matching our NTAG424 test card (7-byte Double UID).
const TEST_UID: [u8; 7] = [0x04, 0x33, 0x65, 0xFA, 0x96, 0x73, 0x80];

/// Spawn a PICC emulation thread that serves `sessions` activation cycles.
///
/// Each session: activation \u2192 RATS/ATS \u2192 APDU echo loop \u2192 DESELECT.
/// The PICC echoes every received APDU back with SW 9000 appended.
fn run_picc_thread(picc_side: ChannelPicc, sessions: usize) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut transceiver = picc_side;
        let mut config = PiccConfig::new(Uid::Double(TEST_UID));
        // Small FSC (16 bytes) to exercise I-Block chaining.
        config.enable_14443_4(Ats::new(
            Fsci::Fsc16,
            Ta::SAME_D_SUPP,
            Tb::default(),
            Tc::CID_SUPP,
        ));

        let mut picc = Picc::new(&mut transceiver, config);

        for _ in 0..sessions {
            picc.wait_for_activation().unwrap();
            picc.wait_for_rats().unwrap();

            loop {
                match picc.receive_command() {
                    Ok(apdu) => {
                        let mut resp: Vec<u8> = apdu.as_slice().to_vec();
                        resp.extend_from_slice(&[0x90, 0x00]);
                        picc.send_response(&resp).unwrap();
                    }
                    Err(PiccError::Deselected) => break,
                    Err(_) => return,
                }
            }
        }
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[test]
fn test_activation_and_rats() {
    let (mut pcd_side, picc_side) = channel_pair();
    let picc = run_picc_thread(picc_side, 1);

    // ISO14443-3A activation (REQA \u2192 anticollision \u2192 SELECT).
    let activation = activate(&mut pcd_side).unwrap();
    assert_eq!(activation.uid.as_slice(), TEST_UID);
    assert!(activation.sak.iso14443_4_compliant);

    // ISO14443-4 RATS/ATS negotiation.
    let cid = Cid::new(0).unwrap();
    let (mut pcd, ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();
    assert_eq!(ats.format.fsci.fsc(), 16);

    // Deselect so the PICC thread exits cleanly.
    pcd.deselect().unwrap();
    picc.join().unwrap();
}

#[test]
fn test_apdu_exchange() {
    let (mut pcd_side, picc_side) = channel_pair();
    let picc = run_picc_thread(picc_side, 1);

    let activation = activate(&mut pcd_side).unwrap();
    assert!(activation.sak.iso14443_4_compliant);

    let cid = Cid::new(0).unwrap();
    let (mut pcd, _ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();

    // Short APDU that fits in a single I-Block.
    let apdu = [0x00, 0xA4, 0x04, 0x00];
    let response = pcd.exchange(&apdu).unwrap();

    // PICC echoes the command back with SW 9000.
    let expected: Vec<u8> = apdu.iter().copied().chain([0x90, 0x00]).collect();
    assert_eq!(response.as_slice(), expected.as_slice());

    pcd.deselect().unwrap();
    picc.join().unwrap();
}

#[test]
fn test_chaining() {
    let (mut pcd_side, picc_side) = channel_pair();
    let picc = run_picc_thread(picc_side, 1);

    let activation = activate(&mut pcd_side).unwrap();
    assert!(activation.sak.iso14443_4_compliant);

    let cid = Cid::new(0).unwrap();
    // FSD=64 so the PICC can send the 32-byte response in one I-Block.
    // The PICC advertises FSC=16 (Fsci::Fsc16 in its ATS), so the PCD
    // must chain any APDU exceeding 12 bytes (FSC 16 − PCB − CID − CRC×2).
    let (mut pcd, ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd64, cid).unwrap();
    assert_eq!(ats.format.fsci.fsc(), 16);

    // Warmup: a short APDU exchange synchronises block numbers so that
    // PCD BN=1 and PICC BN=0 before the chained exchange begins.
    // The protocol handler toggles BN before building R(ACK) in
    // process_iblock; the sender must therefore start chaining with BN=1
    // so the PICC's R(ACK) BN matches.
    let warmup = [0x00, 0xA4, 0x04, 0x00];
    let warmup_resp = pcd.exchange(&warmup).unwrap();
    let warmup_expected: Vec<u8> = warmup.iter().copied().chain([0x90, 0x00]).collect();
    assert_eq!(warmup_resp.as_slice(), warmup_expected.as_slice());

    // 30-byte APDU exceeds FSC=16 (max_inf=12), forcing 3-block chaining.
    let apdu: Vec<u8> = (0x00..0x1E).collect();
    let response = pcd.exchange(&apdu).unwrap();

    // PICC echoes the full command back with SW 9000.
    let expected: Vec<u8> = apdu.iter().copied().chain([0x90, 0x00]).collect();
    assert_eq!(response.as_slice(), expected.as_slice());

    pcd.deselect().unwrap();
    picc.join().unwrap();
}

#[test]
fn test_deselect_and_wupa() {
    let (mut pcd_side, picc_side) = channel_pair();
    let picc = run_picc_thread(picc_side, 2);

    // ── Session 1: REQA activation ──
    let activation = activate(&mut pcd_side).unwrap();
    assert_eq!(activation.uid.as_slice(), TEST_UID);

    let cid = Cid::new(0).unwrap();
    let (mut pcd, _ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();

    let apdu = [0x00, 0xB0, 0x00, 0x00];
    let response = pcd.exchange(&apdu).unwrap();
    let expected: Vec<u8> = apdu.iter().copied().chain([0x90, 0x00]).collect();
    assert_eq!(response.as_slice(), expected.as_slice());

    pcd.deselect().unwrap();

    // ── Session 2: WUPA re-activation from HALT ──
    let activation = wakeup(&mut pcd_side).unwrap();
    assert_eq!(activation.uid.as_slice(), TEST_UID);

    let (mut pcd, _ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();

    let apdu = [0x00, 0xA4, 0x04, 0x00];
    let response = pcd.exchange(&apdu).unwrap();
    let expected: Vec<u8> = apdu.iter().copied().chain([0x90, 0x00]).collect();
    assert_eq!(response.as_slice(), expected.as_slice());

    pcd.deselect().unwrap();
    picc.join().unwrap();
}

#[test]
fn test_pps() {
    let (mut pcd_side, picc_side) = channel_pair();
    let picc = run_picc_thread(picc_side, 1);

    let activation = activate(&mut pcd_side).unwrap();
    assert!(activation.sak.iso14443_4_compliant);

    let cid = Cid::new(0).unwrap();
    let (mut pcd, _ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();

    // PPS negotiation: request 2x bit rate in both directions.
    pcd.pps(Dxi::Dx2, Dxi::Dx2).unwrap();

    // Verify the session still works after PPS.
    let apdu = [0x00, 0xA4, 0x04, 0x00];
    let response = pcd.exchange(&apdu).unwrap();
    let expected: Vec<u8> = apdu.iter().copied().chain([0x90, 0x00]).collect();
    assert_eq!(response.as_slice(), expected.as_slice());

    pcd.deselect().unwrap();
    picc.join().unwrap();
}
