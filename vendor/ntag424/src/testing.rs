// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Shared test plumbing: a mock [`Transport`] and a minimal `block_on`
//! driver that sidesteps pulling in a full async runtime as a dev
//! dependency.
//!
//! Only compiled for `cfg(test)` so it costs nothing in release builds
//! and leaks nothing into the public API.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use crate::crypto::suite::{AesSuite, LrpSuite, SessionSuite, aes_cbc_decrypt};
use crate::session::Authenticated;
use crate::{KeyNumber, Response, Transport};

/// One expected request / canned response pair.
///
/// `expect` is matched exactly against the APDU bytes the code under test
/// transmits; `data`, `sw1`, `sw2` are returned verbatim to the caller.
#[derive(Debug, Clone)]
pub(crate) struct Exchange {
    pub expect: Vec<u8>,
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Exchange {
    pub fn new(expect: &[u8], data: &[u8], sw1: u8, sw2: u8) -> Self {
        Self {
            expect: expect.to_vec(),
            data: data.to_vec(),
            sw1,
            sw2,
        }
    }
}

/// FIFO [`Transport`] mock. Each [`Transport::transmit`] call pops the
/// next queued [`Exchange`], asserts the APDU matches, and returns the
/// canned response. A mismatch or an empty queue panics - both are
/// programming errors in a test.
pub(crate) struct TestTransport {
    exchanges: VecDeque<Exchange>,
}

impl TestTransport {
    pub(crate) fn new(exchanges: impl IntoIterator<Item = Exchange>) -> Self {
        Self {
            exchanges: exchanges.into_iter().collect(),
        }
    }

    pub fn remaining(&self) -> usize {
        self.exchanges.len()
    }
}

/// Uninhabited test transport error.
///
/// [`TestTransport::transmit`] never fails at the transport layer;
/// errors only surface as non-OK status words in the response.
#[derive(Debug)]
pub(crate) enum TestTransportError {}

impl core::fmt::Display for TestTransportError {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for TestTransportError {}

impl Transport for TestTransport {
    type Error = TestTransportError;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Vec<u8>>, Self::Error> {
        let next = self
            .exchanges
            .pop_front()
            .expect("TestTransport: no more exchanges queued");
        assert_eq!(
            apdu,
            next.expect.as_slice(),
            "TestTransport: unexpected APDU",
        );
        Ok(Response {
            data: next.data,
            sw1: next.sw1,
            sw2: next.sw2,
        })
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        panic!("test fixture, not implemented")
    }
}

/// Poll `fut` to completion on the current thread.
///
/// The session layer's `async fn` bodies only `.await` the mock's futures,
/// which resolve synchronously - so a single `poll` is always enough and
/// a `Pending` return would indicate a bug.
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("block_on: future yielded, but tests must not block on I/O"),
    }
}

pub(crate) fn hex_nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex char"),
    }
}

pub(crate) fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    let b = s.as_bytes();
    core::array::from_fn(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
}

pub(crate) fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    let b = s.as_bytes();
    (0..b.len() / 2)
        .map(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
        .collect()
}

/// 256 random bytes used as the payload in hardware-pinned read/write
/// replay tests. Inlined rather than `include_bytes!`'d so the test
/// suite stays self-contained.
#[rustfmt::skip]
pub(crate) const TEST_PAYLOAD_256: [u8; 256] = [
    0xFD, 0x42, 0xF4, 0x74, 0x3B, 0x71, 0x56, 0xA5, 0x8F, 0x9B, 0xC1, 0xA5, 0xBF, 0x84, 0x3A, 0x91,
    0xD3, 0xE9, 0xEE, 0x31, 0xC4, 0x89, 0x78, 0x87, 0x9E, 0x46, 0x0A, 0x7E, 0xC6, 0x2C, 0x68, 0xA4,
    0x9C, 0x8C, 0xA8, 0x6A, 0xF7, 0x4E, 0xC5, 0xED, 0x0F, 0xC2, 0x46, 0xC7, 0xEC, 0xAB, 0xA3, 0x84,
    0x34, 0xFF, 0xD2, 0x65, 0xB2, 0x3F, 0x0B, 0xEB, 0x90, 0xAF, 0x57, 0x5C, 0x44, 0x61, 0x00, 0xB4,
    0xC0, 0xF2, 0xCC, 0xA5, 0x34, 0x39, 0xA3, 0x67, 0x68, 0xF5, 0x81, 0x26, 0xC0, 0x9A, 0x10, 0x59,
    0xB1, 0xBB, 0x02, 0x20, 0x8E, 0x3D, 0x5E, 0x70, 0x61, 0x6B, 0x6F, 0xDF, 0x42, 0x22, 0x66, 0xFE,
    0xDC, 0xFA, 0x25, 0x00, 0xAA, 0x52, 0x72, 0xD6, 0x0D, 0xF1, 0x71, 0x50, 0xBA, 0x80, 0x30, 0xCE,
    0x3B, 0x2A, 0xAB, 0xB2, 0xAA, 0x24, 0x12, 0x3E, 0x1F, 0x99, 0x64, 0x20, 0xBF, 0x0F, 0x48, 0x9D,
    0x41, 0x7E, 0x1D, 0xD4, 0xF6, 0x77, 0x7C, 0xFF, 0x9D, 0xD1, 0x4A, 0x92, 0x6D, 0x09, 0x05, 0x39,
    0xAD, 0xF8, 0xE3, 0xCC, 0xC1, 0xEB, 0xF0, 0xDC, 0xC0, 0xF1, 0x09, 0x34, 0x3E, 0x53, 0xFB, 0x9A,
    0x8E, 0x56, 0x9A, 0x77, 0xDE, 0xC0, 0x51, 0x7E, 0x70, 0x0A, 0x1E, 0x0C, 0x07, 0x9F, 0x70, 0x99,
    0x8D, 0x62, 0x91, 0xF7, 0x0E, 0x41, 0x86, 0x89, 0x71, 0x50, 0xE0, 0x12, 0x5C, 0xE6, 0x5A, 0xB2,
    0xE7, 0xBE, 0x82, 0x66, 0x06, 0x13, 0x1B, 0x8E, 0xA0, 0x91, 0x42, 0x82, 0x3C, 0x73, 0xCF, 0xB9,
    0x5B, 0x20, 0x08, 0xF6, 0x7B, 0x6F, 0x4E, 0x7F, 0xD0, 0x43, 0xB9, 0x7B, 0xCA, 0x03, 0x3F, 0x7F,
    0x70, 0x6A, 0xEF, 0xBB, 0x06, 0x0E, 0xAD, 0x59, 0x4C, 0xC7, 0x77, 0x9C, 0x12, 0x69, 0x0E, 0x62,
    0x66, 0x36, 0x53, 0xB5, 0x42, 0x80, 0x84, 0xF2, 0xCD, 0xDF, 0x80, 0x06, 0xF2, 0x7C, 0x82, 0x57,
];

/// AES Key0 session from real hardware (TI=085BC941, factory-default all-zero key).
pub(crate) fn aes_key0_suite_085bc941() -> (AesSuite, [u8; 4]) {
    let key = [0u8; 16];
    let rnd_a = hex_array::<16>("C4028B41E6F497099C7087768E78A191");
    let mut rnd_b = hex_array::<16>("7858A0B9DBC468F0FF1B2F773D6DF9FC");
    aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();
    (
        AesSuite::derive(&key, &rnd_a, &rnd_b),
        hex_array("085BC941"),
    )
}

/// LRP Key0 session from real hardware (TI=BBE12900, factory-default all-zero key).
pub(crate) fn lrp_key0_suite_bbe12900() -> (LrpSuite, [u8; 4]) {
    let key = [0u8; 16];
    let rnd_a = hex_array::<16>("0272F1390C4B8EC7D3E43308D4B41EC3");
    // LRP Part1 response = 01 || RndB; RndB is plaintext (no decrypt needed).
    let rnd_b = hex_array::<16>("57E5BF7AF415C4C8B330442EC1F265E9");
    // enc_ctr=1: AuthenticateLRPFirst decrypts one block during the handshake.
    (
        LrpSuite::derive(&key, &rnd_a, &rnd_b).with_enc_ctr(1),
        hex_array("BBE12900"),
    )
}

/// AES Key3 `Authenticated` state from real hardware (TI=085BC941, factory-default all-zero key).
pub(crate) fn aes_key3_state_hw(cmd_counter: u16) -> Authenticated<AesSuite> {
    let key = [0u8; 16];
    let rnd_a = hex_array::<16>("30288E8925277FAC5A6D6144341C238E");
    let mut rnd_b = hex_array::<16>("C8FC6F266D55CA43D3BBDE4CC8479AC2");
    aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();
    let suite = AesSuite::derive(&key, &rnd_a, &rnd_b);
    Authenticated::non_first(suite, hex_array("085BC941"), cmd_counter, KeyNumber::Key3)
}

/// LRP Key3 `Authenticated` state from real hardware (TI=AFF75859, factory-default all-zero key).
pub(crate) fn lrp_key3_state_hw(cmd_counter: u16, enc_ctr: u32) -> Authenticated<LrpSuite> {
    let key = [0u8; 16];
    let rnd_a = hex_array::<16>("8177E38B5CF5969189F929D0BF63B60B");
    // LRP Part1 response = 01 || RndB; RndB is plaintext (no decrypt needed).
    let rnd_b = hex_array::<16>("37297005F8AE7E195634AB2C13BE1A8D");
    // enc_ctr accumulates across commands in the same session:
    // ReadData 128B + M2 pad = 9 blocks → enc_ctr 9; WriteData 8B + M2 pad = 1
    // block → enc_ctr 10; ReadData readback 8B + M2 pad = 1 block → enc_ctr 11.
    let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b).with_enc_ctr(enc_ctr);
    Authenticated::non_first(suite, hex_array("AFF75859"), cmd_counter, KeyNumber::Key3)
}

/// AES Key3 `Authenticated` state from real hardware for MAC-only proprietary-file captures.
pub(crate) fn aes_key3_mac_state_hw(cmd_counter: u16) -> Authenticated<AesSuite> {
    let key = [0u8; 16];
    let rnd_a = hex_array::<16>("24BF204C43B6941047265242A23724F8");
    let mut rnd_b = hex_array::<16>("2FE216D6F86B1CBD8937C41D55073383");
    aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b).unwrap();
    let suite = AesSuite::derive(&key, &rnd_a, &rnd_b);
    Authenticated::new(suite, hex_array("59237C63"), KeyNumber::Key3).tap_counter(cmd_counter)
}

/// LRP Key3 `Authenticated` state from real hardware for MAC-only proprietary-file captures.
pub(crate) fn lrp_key3_mac_state_hw(cmd_counter: u16) -> Authenticated<LrpSuite> {
    let key = [0u8; 16];
    let rnd_a = hex_array::<16>("033444D60AC1ED31D2753FF86140D94F");
    // LRP Part1 response = 01 || RndB; RndB is plaintext (no decrypt needed).
    let rnd_b = hex_array::<16>("F344BE464EB5E84CB349EF0716C2DC06");
    // enc_ctr=1: AuthenticateLRPFirst decrypts one block during the handshake.
    let suite = LrpSuite::derive(&key, &rnd_a, &rnd_b).with_enc_ctr(1);
    Authenticated::new(suite, hex_array("4F4B4865"), KeyNumber::Key3).tap_counter(cmd_counter)
}

trait TapCounter<S: SessionSuite> {
    fn tap_counter(self, cmd_counter: u16) -> Self;
}

impl<S: SessionSuite> TapCounter<S> for Authenticated<S> {
    fn tap_counter(mut self, cmd_counter: u16) -> Self {
        for _ in 0..cmd_counter {
            self.advance_counter();
        }
        self
    }
}
