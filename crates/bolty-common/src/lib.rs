//! Shared compile-time constants for the bolty-rs workspace.
//!
//! `#![no_std]`-compatible crate whose constants are used across Bolt Card
//! firmware and tooling for NTAG424 key management.
//!
//! Key items: `FACTORY_KEY`, `KEY_VERSION_BLANK`, `UID_LEN`, `NUM_KEYS`.

#![no_std]

pub const FACTORY_KEY: [u8; 16] = [0u8; 16];
pub const KEY_VERSION_BLANK: u8 = 0x00;
pub const UID_LEN: usize = 7;
pub const NUM_KEYS: usize = 5;
