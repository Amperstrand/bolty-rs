mod mock;

use bolty_ntag::{
    BurnParams, FACTORY_KEY, FACTORY_KEY_VERSION, KeySet, burn, check_key_versions, read_uid,
    wipe,
};
use mock::{MockTransport, UID, block_on};
use ntag424::{
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::{KeyNumber, file_settings::CryptoMode},
};

fn test_keys() -> KeySet {
    [[0x10; 16], [0x21; 16], [0x32; 16], [0x43; 16], [0x54; 16]]
}

#[test]
fn read_uid_returns_fixed_uid_without_modification() {
    let mut transport = MockTransport::new();

    let uid = block_on(read_uid(&mut transport)).unwrap();

    assert_eq!(uid, UID);
}

fn burn_lnurl() -> &'static str {
    "https://example.com/lnurl?[[p={picc:uid+ctr}&cmac={mac}"
}

#[test]
fn burn_programs_ndef_sdm_and_keys() {
    let keys = test_keys();
    let params = BurnParams {
        lnurl: burn_lnurl(),
        keys,
        key_version: 0x42,
        current_key: FACTORY_KEY,
    };
    let plan = sdm_url_config(burn_lnurl(), CryptoMode::Aes, SdmUrlOptions::new()).unwrap();
    let mut transport = MockTransport::new();

    let result = block_on(burn(
        &mut transport,
        &params,
        [
            0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F, 0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75,
            0x36, 0x0F,
        ],
    ))
    .unwrap();

    assert_eq!(result.uid, UID);
    assert_eq!(transport.ndef(), plan.ndef_bytes.as_slice());
    assert_eq!(transport.keys(), &keys);
    assert_eq!(transport.key_versions(), &[0x42; 5]);

    let settings = ntag424::types::FileSettingsView::decode(transport.file_settings()).unwrap();
    assert!(settings.sdm.is_some());
}

#[test]
fn wipe_restores_factory_keys_and_zeros_ndef() {
    let keys = test_keys();
    let key_versions = [0x42; 5];
    let plan = sdm_url_config(burn_lnurl(), CryptoMode::Aes, SdmUrlOptions::new()).unwrap();
    let original_len = plan.ndef_bytes.len();
    let mut transport = MockTransport::provisioned(
        keys,
        key_versions,
        plan.ndef_bytes,
        vec![0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00],
    );

    let result = block_on(wipe(
        &mut transport,
        &keys,
        [
            0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F, 0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75,
            0x36, 0x0F,
        ],
    ))
    .unwrap();

    assert_eq!(result.uid, UID);
    assert_eq!(transport.keys(), &[[0u8; 16]; 5]);
    assert_eq!(transport.key_versions(), &[FACTORY_KEY_VERSION; 5]);
    assert!(transport.ndef()[..original_len].iter().all(|b| *b == 0));
    assert_eq!(transport.keys()[0], FACTORY_KEY);
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

    let got = block_on(check_key_versions(
        &mut transport,
        &keys[0],
        [
            0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F, 0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75,
            0x36, 0x0F,
        ],
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
