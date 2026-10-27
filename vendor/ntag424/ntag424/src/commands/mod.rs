// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

mod authenticate;
mod change_file_settings;
mod change_key;
mod get_card_uid;
mod get_file_counters;
mod get_file_settings;
mod get_key_version;
mod get_tt_status;
mod get_version;
mod iso_read_binary;
mod iso_select_file;
mod iso_update_binary;
mod read_data;
#[cfg(feature = "originality")]
mod read_sig;
mod secure_channel;
mod set_configuration;
mod write_data;

pub(crate) use authenticate::{
    AuthResult, authenticate_ev2_first_aes, authenticate_ev2_first_lrp,
    authenticate_ev2_non_first_aes, authenticate_ev2_non_first_lrp,
};
pub(crate) use change_file_settings::change_file_settings;
pub(crate) use change_key::{change_key, change_master_key};
pub(crate) use get_card_uid::get_card_uid;
pub(crate) use get_file_counters::get_file_counters;
pub(crate) use get_file_settings::{get_file_settings, get_file_settings_mac};
pub(crate) use get_key_version::get_key_version;
pub(crate) use get_tt_status::get_tt_status;
pub(crate) use get_version::{get_version, get_version_mac};
pub(crate) use iso_read_binary::iso_read_binary;
pub(crate) use iso_select_file::{iso_select_ef_by_fid, select_ndef_application};
pub(crate) use iso_update_binary::iso_update_binary;
pub(crate) use read_data::{read_data_full, read_data_mac, read_data_plain};
#[cfg(feature = "originality")]
pub(crate) use read_sig::{read_sig, read_sig_mac};
pub(crate) use secure_channel::SecureChannel;
pub(crate) use set_configuration::set_configuration;
pub(crate) use write_data::{write_data_full, write_data_mac, write_data_plain};
