// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

mod aes;
mod lrp;

pub(crate) use aes::authenticate_ev2_first as authenticate_ev2_first_aes;
pub(crate) use aes::authenticate_ev2_non_first as authenticate_ev2_non_first_aes;
pub(crate) use lrp::authenticate_ev2_first as authenticate_ev2_first_lrp;
pub(crate) use lrp::authenticate_ev2_non_first as authenticate_ev2_non_first_lrp;

#[derive(Debug)]
pub(crate) struct AuthResult<S> {
    pub(crate) suite: S,
    /// Transaction identifier, constant for the lifetime of the authenticated
    /// session.
    ///
    /// Used together with `cmd_counter` to prevent replay attacks.
    pub(crate) ti: [u8; 4],
    pub(crate) pd_cap2: [u8; 6],
    pub(crate) pcd_cap2: [u8; 6],
}
