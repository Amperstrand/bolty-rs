// Tests assert on known fixtures: panicking on malformed data IS the
// failure mode this suite wants (workspace warn-level lints stay
// enforced for all production code).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod mock;

use bolty_core::secret::{AesKey, CardKeys};
use bolty_ntag::{
    BurnParams, Error, FACTORY_KEY, FACTORY_KEY_VERSION, burn, check_key_versions, f5probe,
    preflight, read_uid, wipe,
};
use mock::{MockTransport, UID, block_on};
use ntag424::{
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::{KeyNumber, file_settings::CryptoMode},
};

/// Read Free, write/read-write/change K0 — wire bytes `00 E0` (TSX
/// setBoltCardFileSettings / NT4H2421Gx Rev 3.0 Table 8 fn[1]).
fn locked_access_rights() -> ntag424::types::file_settings::AccessRights {
    ntag424::types::file_settings::AccessRights {
        read: ntag424::types::file_settings::Access::Free,
        write: ntag424::types::file_settings::Access::Key(KeyNumber::Key0),
        read_write: ntag424::types::file_settings::Access::Key(KeyNumber::Key0),
        change: ntag424::types::file_settings::Access::Key(KeyNumber::Key0),
    }
}

/// Factory NDEF access rights — wire bytes `E0 EE`.
fn factory_access_rights() -> ntag424::types::file_settings::AccessRights {
    ntag424::types::file_settings::AccessRights {
        read: ntag424::types::file_settings::Access::Free,
        write: ntag424::types::file_settings::Access::Free,
        read_write: ntag424::types::file_settings::Access::Free,
        change: ntag424::types::file_settings::Access::Key(KeyNumber::Key0),
    }
}

type RawKeySet = [[u8; 16]; 5];

const RND_A: [u8; 16] = [
    0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F, 0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75, 0x36, 0x0F,
];

fn test_keys() -> RawKeySet {
    [[0x10; 16], [0x21; 16], [0x32; 16], [0x43; 16], [0x54; 16]]
}

fn to_cardkeys(arr: RawKeySet) -> CardKeys {
    CardKeys {
        k0: AesKey::new(arr[0]),
        k1: AesKey::new(arr[1]),
        k2: AesKey::new(arr[2]),
        k3: AesKey::new(arr[3]),
        k4: AesKey::new(arr[4]),
    }
}

fn factory_cardkeys() -> CardKeys {
    to_cardkeys([FACTORY_KEY; 5])
}

#[test]
fn read_uid_returns_fixed_uid_without_modification() {
    let mut transport = MockTransport::new();

    let uid = block_on(read_uid(&mut transport)).unwrap();

    assert_eq!(uid, UID);
}

#[test]
fn preflight_returns_uid_for_ntag424() {
    let mut transport = MockTransport::new();

    let uid = block_on(preflight(&mut transport)).unwrap();

    assert_eq!(uid, UID);
}

#[test]
fn preflight_and_burn_pipeline() {
    let keys = test_keys();
    let params = burn_params(burn_lnurl(), keys);
    let mut transport = MockTransport::new();

    let uid = block_on(preflight(&mut transport)).unwrap();
    assert_eq!(uid, UID);

    let result = block_on(burn(&mut transport, &params, AesKey::new(RND_A))).unwrap();

    assert_eq!(result.uid, UID);
    assert_eq!(transport.keys(), &keys);
}

fn burn_lnurl() -> &'static str {
    "https://example.com/lnurl?p={picc:uid+ctr}&c=[[{mac}"
}

fn burn_params(lnurl: &'static str, keys: RawKeySet) -> BurnParams<'static> {
    BurnParams {
        lnurl,
        keys: to_cardkeys(keys),
        key_version: 0x42,
        current_key: AesKey::new(FACTORY_KEY),
        previous_keys: factory_cardkeys(),
    }
}

#[test]
fn burn_programs_ndef_sdm_and_keys() {
    let keys = test_keys();
    let params = burn_params(burn_lnurl(), keys);
    let plan = sdm_url_config(burn_lnurl(), CryptoMode::Aes, SdmUrlOptions::new()).unwrap();
    let mut transport = MockTransport::new();

    let result = block_on(burn(&mut transport, &params, AesKey::new(RND_A))).unwrap();

    assert_eq!(result.uid, UID);
    assert_eq!(transport.ndef(), plan.ndef_bytes.as_slice());
    assert_eq!(transport.keys(), &keys);
    assert_eq!(transport.key_versions(), &[0x42; 5]);

    let settings = ntag424::types::FileSettingsView::decode(transport.file_settings()).unwrap();
    assert!(settings.sdm.is_some());
}

#[test]
fn reburn_replaces_existing_keys() {
    let first_keys = test_keys();
    let second_keys: RawKeySet = [[0xAA; 16], [0xBB; 16], [0xCC; 16], [0xDD; 16], [0xEE; 16]];

    let mut transport = MockTransport::new();

    block_on(burn(
        &mut transport,
        &burn_params(burn_lnurl(), first_keys),
        AesKey::new([0x13; 16]),
    ))
    .unwrap();

    assert_eq!(transport.keys(), &first_keys);
    assert_eq!(transport.key_versions(), &[0x42; 5]);

    let reburn_params = BurnParams {
        lnurl: burn_lnurl(),
        keys: to_cardkeys(second_keys),
        key_version: 0x99,
        current_key: AesKey::new(first_keys[0]),
        previous_keys: to_cardkeys(first_keys),
    };

    block_on(burn(
        &mut transport,
        &reburn_params,
        AesKey::new([0x27; 16]),
    ))
    .unwrap();

    assert_eq!(transport.keys(), &second_keys);
    assert_eq!(transport.key_versions(), &[0x99; 5]);
}

#[test]
fn wipe_restores_factory_keys_and_zeros_ndef() {
    let keys = test_keys();
    let key_versions = [0x42; 5];
    let plan = sdm_url_config(burn_lnurl(), CryptoMode::Aes, SdmUrlOptions::new()).unwrap();
    let mut transport = MockTransport::provisioned(
        keys,
        key_versions,
        plan.ndef_bytes,
        vec![0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00],
    );

    let result = block_on(wipe(&mut transport, &to_cardkeys(keys), AesKey::new(RND_A))).unwrap();

    assert_eq!(result.uid, UID);
    assert_eq!(transport.keys(), &[[0u8; 16]; 5]);
    assert_eq!(transport.key_versions(), &[FACTORY_KEY_VERSION; 5]);
    assert_eq!(
        &transport.ndef()[..2],
        &[0x00, 0x00],
        "NDEF should be empty (NLEN=0)"
    );
    assert_eq!(transport.keys()[0], FACTORY_KEY);
    // Issue #232: the wipe must deliver the §8.2.3 FACTORY shape —
    // FileOption SDM enable bit CLEAR, no SDM block — so a post-wipe
    // GetFileSettings decodes sdm == None (previously
    // with_sdm(Sdm::disabled()) left a Some(Sdm{..}) shell that made
    // the promised cleared state unobservable).
    let settings = ntag424::types::FileSettingsView::decode(transport.file_settings()).unwrap();
    assert!(
        settings.sdm.is_none(),
        "post-wipe file settings must decode sdm: None, got: {:?}",
        settings.sdm
    );
}

#[test]
fn burn_locks_ndef_write_access_per_datasheet_table8() {
    let keys = test_keys();
    let params = burn_params(burn_lnurl(), keys);
    let mut transport = MockTransport::new();

    block_on(burn(&mut transport, &params, AesKey::new(RND_A))).unwrap();

    let settings = ntag424::types::FileSettingsView::decode(transport.file_settings()).unwrap();
    // NT4H2421Gx Rev 3.0 Table 8 fn[1]: burn must lock NDEF write access
    // (audit A4 finding F1).
    assert_eq!(settings.access_rights, locked_access_rights());

    // Byte-exact wire pin (audit adjudication D1): the burn ChangeFileSettings
    // carries access-rights wire bytes 00 E0 — the little-endian Table-7
    // encode of Read=Free, Write/RW/Change=K0, identical to AN12196 Table 12
    // (post-personalization example) and Table 19 CmdData. The mock splices
    // the decrypted patch bytes raw, so this asserts the actual wire bytes.
    #[allow(clippy::indexing_slicing)]
    let ar_wire = &transport.file_settings()[2..4];
    assert_eq!(ar_wire, &[0x00, 0xE0]);
}

#[test]
fn burn_then_reburn_still_locks_access_rights() {
    let keys = test_keys();
    let mut transport = MockTransport::new();

    block_on(burn(
        &mut transport,
        &burn_params(burn_lnurl(), keys),
        AesKey::new(RND_A),
    ))
    .unwrap();

    let reburn_keys: RawKeySet = [[0xAA; 16], [0xBB; 16], [0xCC; 16], [0xDD; 16], [0xEE; 16]];
    let reburn_params = BurnParams {
        lnurl: burn_lnurl(),
        keys: to_cardkeys(reburn_keys),
        key_version: 0x99,
        current_key: AesKey::new(keys[0]),
        previous_keys: to_cardkeys(keys),
    };

    block_on(burn(
        &mut transport,
        &reburn_params,
        AesKey::new([0x27; 16]),
    ))
    .unwrap();

    let settings = ntag424::types::FileSettingsView::decode(transport.file_settings()).unwrap();
    assert_eq!(settings.access_rights, locked_access_rights());
    #[allow(clippy::indexing_slicing)]
    let ar_wire = &transport.file_settings()[2..4];
    assert_eq!(ar_wire, &[0x00, 0xE0]);
}

#[test]
fn wipe_restores_factory_access_rights() {
    let keys = test_keys();
    // Externally burned card shape: TSX forces AR = 00 E0 on setup.
    let mut transport = MockTransport::provisioned(
        keys,
        [0x42; 5],
        Vec::new(),
        vec![0x00, 0x00, 0x00, 0xE0, 0x00, 0x01, 0x00],
    );

    block_on(wipe(&mut transport, &to_cardkeys(keys), AesKey::new(RND_A))).unwrap();

    let settings = ntag424::types::FileSettingsView::decode(transport.file_settings()).unwrap();
    // DET:68 "Restore the NDEF file settings to default values" includes the
    // access rights (audit A4 finding F3).
    assert_eq!(settings.access_rights, factory_access_rights());

    // Byte-exact wire pin (audit adjudication D1, RE-ADJUDICATED for
    // #232): the wipe ChangeFileSettings now delivers the §8.2.3 FACTORY
    // shape — file_option 00 (SDM enable bit CLEAR) + AR E0 EE + size,
    // with NO SDM block at all: `00 00 E0EE 000100`. The pre-#232 shape
    // was byte-identical to TSX resetFileSettings "40 E0EE 01 FFFF"
    // (SDM flagged ON, mirrors off) — behaviorally inert but decodable
    // only as Some(Sdm{..}), so the cleared state was unobservable
    // (#232). Post-wipe GetFileSettings now decodes sdm: None, and the
    // blob is byte-identical to a factory card's default settings.
    assert_eq!(
        transport.file_settings(),
        &[0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00]
    );
}

#[test]
fn check_key_versions_reads_all_five_versions() {
    let keys = test_keys();
    let versions = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4];
    let mut transport = MockTransport::provisioned(
        keys,
        versions,
        Vec::new(),
        vec![0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00],
    );

    let provisioned_keys = to_cardkeys(keys);
    let got = block_on(check_key_versions(
        &mut transport,
        &provisioned_keys.k0,
        AesKey::new(RND_A),
    ))
    .unwrap();

    assert_eq!(got, versions);
}

#[test]
fn diversify_ntag424_matches_known_vector() {
    let master = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let uid = [0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80];
    let sys = b"bolty";

    let keys = [
        diversify_ntag424(&master, &uid, KeyNumber::Key0, sys),
        diversify_ntag424(&master, &uid, KeyNumber::Key1, sys),
        diversify_ntag424(&master, &uid, KeyNumber::Key2, sys),
        diversify_ntag424(&master, &uid, KeyNumber::Key3, sys),
        diversify_ntag424(&master, &uid, KeyNumber::Key4, sys),
    ];

    assert_eq!(
        keys,
        [
            [
                191, 138, 71, 221, 192, 21, 221, 57, 232, 158, 85, 208, 213, 15, 131, 42
            ],
            [
                16, 157, 13, 15, 8, 116, 143, 18, 22, 50, 150, 110, 117, 178, 82, 195
            ],
            [
                248, 15, 32, 87, 0, 241, 204, 63, 177, 21, 174, 184, 57, 242, 86, 26
            ],
            [
                249, 190, 243, 151, 213, 210, 137, 199, 253, 49, 204, 130, 127, 89, 208, 249
            ],
            [
                170, 199, 143, 216, 166, 219, 1, 89, 100, 164, 126, 101, 112, 147, 150, 106
            ],
        ]
    );
}

// ------------------------------------------------------ sdm_mirroring ----

use bolty_ntag::{SdmMirroring, safe_inspect};

fn burned_sdm_transport() -> MockTransport {
    let keys = test_keys();
    let params = burn_params(burn_lnurl(), keys);
    let mut transport = MockTransport::new();
    block_on(burn(&mut transport, &params, AesKey::new(RND_A))).unwrap();
    transport
}

#[test]
fn safe_inspect_reports_live_mirroring_when_ndef_ticks_between_reads() {
    let mut transport = burned_sdm_transport();
    let ticked = transport.ndef().to_vec();
    #[allow(clippy::indexing_slicing)]
    let ticked = {
        let mut t = ticked;
        // Flip a byte inside the SDM-mirrored p= region: the card served
        // fresh PICC data on the second read.
        let last = t.len() - 1;
        t[last] ^= 0x01;
        t
    };
    transport.override_next_ndef_read(ticked);

    let result = block_on(safe_inspect(&mut transport, None, None)).unwrap();

    assert_eq!(result.sdm_mirroring, SdmMirroring::Live);
    // Key-free inspect never claims cryptographic verification.
    assert!(result.sdm_verification.is_none());
}

#[test]
fn safe_inspect_reports_static_when_two_reads_are_identical() {
    let mut transport = burned_sdm_transport();

    let result = block_on(safe_inspect(&mut transport, None, None)).unwrap();

    assert_eq!(result.sdm_mirroring, SdmMirroring::Static);
}

#[test]
fn safe_inspect_reports_off_when_sdm_not_configured() {
    // Factory-fresh mock: DEFAULT_FILE_SETTINGS carry no SDM config.
    let mut transport = MockTransport::new();
    transport.override_next_ndef_read(Vec::new());

    let result = block_on(safe_inspect(&mut transport, None, None)).unwrap();

    assert_eq!(result.sdm_mirroring, SdmMirroring::Off);
}

// ── f5probe (#233): content-preserving write leg + non-blank gate ──────

#[test]
fn f5probe_refuses_non_blank_ndef_without_force() {
    let mut ndef = vec![0u8; 256];
    ndef[1] = 0x21; // any nonzero byte = data present
    let mut transport = MockTransport::provisioned(
        [[0u8; 16]; 5],
        [0u8; 5],
        ndef.clone(),
        MockTransport::default_file_settings(),
    );

    let err = block_on(f5probe(&mut transport, RND_A, false)).unwrap_err();
    match err {
        Error::NdefNotEmpty { len } => assert_eq!(len, 256),
        other => panic!("expected NdefNotEmpty, got {other:?}"),
    }
    // untouched: the refusal fires before ANY interleaved op
    assert_eq!(transport.ndef(), &ndef[..]);
}

#[test]
fn f5probe_blank_ndef_probes_without_force() {
    let mut transport = MockTransport::provisioned(
        [[0u8; 16]; 5],
        [0u8; 5],
        vec![0u8; 256],
        MockTransport::default_file_settings(),
    );

    let r = block_on(f5probe(&mut transport, RND_A, false)).unwrap();
    assert_eq!(
        (
            r.read_f5,
            r.read_ad,
            r.write_f5,
            r.write_8d,
            r.write_skipped
        ),
        (3, 3, 2, 1, false)
    );
    assert_eq!(transport.writes_served, 1);
    assert!(transport.ndef().iter().all(|&b| b == 0));
}

#[test]
fn f5probe_gate_survives_applet_len0_quirk() {
    // J3R180 applet: length=0 plain reads answer EMPTY (hardware-observed
    // 2026-10-28) — without the explicit-window fallback the #233 gate
    // saw nothing and happily probed a card with residual NDEF
    let mut ndef = vec![0u8; 256];
    ndef[1] = 0x21;
    let mut transport = MockTransport::provisioned(
        [[0u8; 16]; 5],
        [0u8; 5],
        ndef.clone(),
        MockTransport::default_file_settings(),
    );
    transport.applet_len0_empty = true;

    let err = block_on(f5probe(&mut transport, RND_A, false)).unwrap_err();
    assert!(matches!(err, Error::NdefNotEmpty { .. }));
    assert_eq!(transport.ndef(), &ndef[..]);

    // and the forced run is read-only through the quirk — content intact
    let mut transport = MockTransport::provisioned(
        [[0u8; 16]; 5],
        [0u8; 5],
        ndef.clone(),
        MockTransport::default_file_settings(),
    );
    transport.applet_len0_empty = true;
    let r = block_on(f5probe(&mut transport, RND_A, true)).unwrap();
    assert_eq!((r.read_f5, r.read_ad, r.write_skipped), (3, 3, true));
    assert_eq!(
        transport.writes_served, 0,
        "forced non-blank run must not write"
    );
    assert_eq!(transport.ndef(), &ndef[..]);
}

#[test]
fn f5probe_forced_non_blank_is_read_only() {
    // hardware-taught (J3R180, 2026-10-28): with SDM mirroring the
    // ReadData view is PROCESSED data, not the raw template — a
    // write-back of the read view corrupted NLEN live. Forced runs on a
    // non-blank card therefore skip the 8D leg entirely.
    let mut ndef = vec![0u8; 256];
    ndef[0] = 0x00;
    ndef[1] = 0x21;
    let mut transport = MockTransport::provisioned(
        [[0u8; 16]; 5],
        [0u8; 5],
        ndef.clone(),
        MockTransport::default_file_settings(),
    );

    let r = block_on(f5probe(&mut transport, RND_A, true)).unwrap();
    assert_eq!(
        (
            r.read_f5,
            r.read_ad,
            r.write_f5,
            r.write_8d,
            r.write_skipped
        ),
        (3, 3, 0, 0, true)
    );
    assert_eq!(transport.writes_served, 0);
    assert_eq!(
        transport.ndef(),
        &ndef[..],
        "no byte may move on a forced run"
    );
}
