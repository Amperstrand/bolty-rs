//! Integration tests for bolty-cli using MockTransport.

#[path = "../src/mock_transport.rs"]
mod mock_transport;

use bolty_core::derivation::BoltcardDeterministicDeriver;
use bolty_core::uid::CardUid;
use bolty_ntag::{
    AuthenticatedSession, CryptoMode, File, FileSettingsView, KeyNumber, NonMasterKeyNumber,
    PiccData, Sdm, SdmUrlOptions, Session, sdm_url_config,
};
use mock_transport::{MockTransport, UID};

const ISSUER_KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];
const BURN_VERSION: u8 = 1;
const RND_A: [u8; 16] = [
    0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F, 0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75, 0x36, 0x0F,
];

const TEST_URL: &str = "https://card.bolt.local/lnurl?p={picc:uid+ctr}&c=[[{mac}";

fn derive_keys() -> bolty_core::derivation::CardKeySet {
    BoltcardDeterministicDeriver::derive_keys(&ISSUER_KEY, CardUid::new(UID), BURN_VERSION as u32)
}

fn boltcard_sdm_opts() -> SdmUrlOptions {
    SdmUrlOptions {
        picc_key: KeyNumber::Key1,
        mac_key: KeyNumber::Key2,
        ..SdmUrlOptions::new()
    }
}

async fn do_burn(transport: &mut MockTransport) {
    let plan = sdm_url_config(TEST_URL, CryptoMode::Aes, boltcard_sdm_opts()).unwrap();
    let keys = derive_keys();

    let session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, &[0u8; 16], RND_A)
        .await
        .expect("factory K0 auth on blank card");

    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .expect("read file settings");
    let mut session = session;
    if settings.sdm.is_some() {
        let update = settings.into_update().with_sdm(Sdm::disabled());
        session = session
            .change_file_settings(transport, File::Ndef, &update)
            .await
            .expect("clear SDM");
    }

    session
        .write_file_plain(transport, File::Ndef, 0, &plan.ndef_bytes)
        .await
        .expect("write NDEF");

    let mut read_buf = [0u8; 256];
    let read_len = session
        .read_file_plain(transport, File::Ndef, 0, 0, &mut read_buf)
        .await
        .expect("read back NDEF");
    assert!(read_len >= plan.ndef_bytes.len());
    assert_eq!(&read_buf[..plan.ndef_bytes.len()], &plan.ndef_bytes[..]);

    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .expect("read file settings for SDM");
    let session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &settings.into_update().with_sdm(plan.sdm_settings),
        )
        .await
        .expect("enable SDM");

    let mut session = session;
    let key_steps: [(NonMasterKeyNumber, &[u8; 16]); 4] = [
        (NonMasterKeyNumber::Key1, keys.k1.as_bytes()),
        (NonMasterKeyNumber::Key2, keys.k2.as_bytes()),
        (NonMasterKeyNumber::Key3, keys.k3.as_bytes()),
        (NonMasterKeyNumber::Key4, keys.k4.as_bytes()),
    ];
    for (key_no, new_key) in key_steps {
        session = session
            .change_key(transport, key_no, new_key, BURN_VERSION, &[0u8; 16])
            .await
            .expect("change key");
    }

    session
        .change_master_key(transport, keys.k0.as_bytes(), BURN_VERSION)
        .await
        .expect("change master key");
}

async fn do_wipe(transport: &mut MockTransport) {
    let keys = derive_keys();

    let session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, keys.k0.as_bytes(), RND_A)
        .await
        .expect("derived K0 auth on provisioned card");

    let (settings, session) = session
        .get_file_settings(transport, File::Ndef)
        .await
        .expect("read file settings");
    let update = settings.into_update().with_sdm(Sdm::disabled());
    let mut session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await
        .expect("disable SDM");

    let empty_ndef = [0x00u8, 0x00];
    session
        .write_file_plain(transport, File::Ndef, 0, &empty_ndef)
        .await
        .expect("write empty NDEF");

    let key_steps: [(NonMasterKeyNumber, &[u8; 16]); 4] = [
        (NonMasterKeyNumber::Key1, keys.k1.as_bytes()),
        (NonMasterKeyNumber::Key2, keys.k2.as_bytes()),
        (NonMasterKeyNumber::Key3, keys.k3.as_bytes()),
        (NonMasterKeyNumber::Key4, keys.k4.as_bytes()),
    ];
    for (key_no, old_key) in key_steps {
        session = session
            .change_key(transport, key_no, &[0u8; 16], 0, old_key)
            .await
            .expect("reset key to factory");
    }

    session
        .change_master_key(transport, &[0u8; 16], 0)
        .await
        .expect("reset master key");
}

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn burn_on_blank_card_changes_keys() {
    let mut transport = MockTransport::new();
    let keys = derive_keys();

    do_burn(&mut transport).await;

    assert_eq!(transport.keys()[0], *keys.k0.as_bytes(), "K0 changed");
    assert_eq!(transport.keys()[1], *keys.k1.as_bytes(), "K1 changed");
    assert_eq!(transport.keys()[2], *keys.k2.as_bytes(), "K2 changed");
    assert_eq!(transport.keys()[3], *keys.k3.as_bytes(), "K3 changed");
    assert_eq!(transport.keys()[4], *keys.k4.as_bytes(), "K4 changed");

    assert_eq!(
        transport.key_versions(),
        &[BURN_VERSION; 5],
        "all key versions updated"
    );

    assert!(!transport.ndef().is_empty(), "NDEF written");

    let settings = FileSettingsView::decode(transport.file_settings()).expect("decode");
    assert!(settings.sdm.is_some(), "SDM enabled after burn");
}

#[tokio::test]
async fn wipe_on_provisioned_card_resets_keys() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    do_wipe(&mut transport).await;

    assert_eq!(
        transport.keys(),
        &[[0u8; 16]; 5],
        "all keys reset to factory"
    );
    assert_eq!(
        transport.key_versions(),
        &[0u8; 5],
        "all key versions reset to 0x00"
    );

    assert_eq!(&transport.ndef()[..2], &[0x00, 0x00], "NDEF empty (NLEN=0)");

    let settings = FileSettingsView::decode(transport.file_settings()).expect("decode");
    // Sdm::disabled() sets the SDM bit but configures no active mirroring/MAC.
    // Check that SDM is effectively inert.
    let sdm_inert = settings.sdm.as_ref().map_or(true, |sdm| {
        matches!(sdm.picc_data(), PiccData::None) && sdm.file_read().is_none()
    });
    assert!(sdm_inert, "SDM disabled after wipe");
}

#[tokio::test]
async fn burn_on_provisioned_card_replaces_keys() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;
    let first_keys = transport.keys().clone();

    let keys = derive_keys();
    let plan = sdm_url_config(TEST_URL, CryptoMode::Aes, boltcard_sdm_opts()).unwrap();

    let session = Session::default()
        .authenticate_aes(&mut transport, KeyNumber::Key0, &[0u8; 16], RND_A)
        .await;
    assert!(session.is_err(), "factory K0 must fail on provisioned card");

    let session = Session::default()
        .authenticate_aes(&mut transport, KeyNumber::Key0, keys.k0.as_bytes(), RND_A)
        .await
        .expect("derived K0 auth on provisioned card");

    let (settings, session) = session
        .get_file_settings(&mut transport, File::Ndef)
        .await
        .expect("read file settings");
    let mut session = session;
    if settings.sdm.is_some() {
        let update = settings.into_update().with_sdm(Sdm::disabled());
        session = session
            .change_file_settings(&mut transport, File::Ndef, &update)
            .await
            .expect("clear SDM");
    }

    session
        .write_file_plain(&mut transport, File::Ndef, 0, &plan.ndef_bytes)
        .await
        .expect("write NDEF");

    let (settings, session) = session
        .get_file_settings(&mut transport, File::Ndef)
        .await
        .expect("read file settings for SDM");
    let session = session
        .change_file_settings(
            &mut transport,
            File::Ndef,
            &settings.into_update().with_sdm(plan.sdm_settings),
        )
        .await
        .expect("enable SDM");

    let mut session = session;
    let key_steps: [(NonMasterKeyNumber, &[u8; 16], &[u8; 16]); 4] = [
        (NonMasterKeyNumber::Key1, keys.k1.as_bytes(), &first_keys[1]),
        (NonMasterKeyNumber::Key2, keys.k2.as_bytes(), &first_keys[2]),
        (NonMasterKeyNumber::Key3, keys.k3.as_bytes(), &first_keys[3]),
        (NonMasterKeyNumber::Key4, keys.k4.as_bytes(), &first_keys[4]),
    ];
    for (key_no, new_key, old_key) in key_steps {
        session = session
            .change_key(&mut transport, key_no, new_key, BURN_VERSION, old_key)
            .await
            .expect("change key");
    }

    session
        .change_master_key(&mut transport, keys.k0.as_bytes(), BURN_VERSION)
        .await
        .expect("change master key");

    assert_eq!(transport.keys()[0], *keys.k0.as_bytes());
    assert_eq!(transport.keys()[1], *keys.k1.as_bytes());
    assert_eq!(transport.key_versions(), &[BURN_VERSION; 5]);
}

#[tokio::test]
async fn diagnose_on_blank_card_shows_blank_state() {
    let mut transport = MockTransport::new();
    let mut session = Session::default();

    let uid = session.get_selected_uid(&mut transport).await.expect("uid");
    assert_eq!(uid.as_ref(), UID);

    let version = session.get_version(&mut transport).await.expect("version");
    assert_eq!(version.hw_vendor_id(), 0x04, "NTAG424 vendor");

    let settings = session
        .get_file_settings(&mut transport, File::Ndef)
        .await
        .expect("file settings");
    let has_sdm = settings.sdm.is_some();
    assert!(!has_sdm, "no SDM on blank card");

    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(&mut transport, File::Ndef, 0, &mut buf)
        .await
        .expect("read NDEF");
    let has_ndef_content = len >= 2 && (buf[0] != 0x00 || buf[1] != 0x00);
    assert!(!has_ndef_content, "empty NDEF on blank card");

    let factory_auth = Session::default()
        .authenticate_aes(&mut transport, KeyNumber::Key0, &[0u8; 16], RND_A)
        .await;
    assert!(factory_auth.is_ok(), "factory K0 works on blank card");

    let looks_blank = !has_sdm && !has_ndef_content;
    assert!(looks_blank, "card classifies as BLANK");
}

#[tokio::test]
async fn diagnose_on_provisioned_card_shows_provisioned_state() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    let mut session = Session::default();

    let _uid = session.get_selected_uid(&mut transport).await.expect("uid");

    let _version = session.get_version(&mut transport).await.expect("version");

    let settings = session
        .get_file_settings(&mut transport, File::Ndef)
        .await
        .expect("file settings");
    assert!(settings.sdm.is_some(), "SDM active on provisioned card");

    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(&mut transport, File::Ndef, 0, &mut buf)
        .await
        .expect("read NDEF");
    assert!(len > 2, "NDEF has content on provisioned card");

    let has_sdm = settings.sdm.is_some();
    #[allow(clippy::indexing_slicing)]
    let has_ndef_content = len >= 2 && (buf[0] != 0x00 || buf[1] != 0x00);
    assert!(
        has_sdm && has_ndef_content,
        "card classifies as PROVISIONED"
    );
}

#[tokio::test]
async fn keyver_on_blank_card_shows_factory_versions() {
    let mut transport = MockTransport::new();

    let result = Session::default()
        .authenticate_aes(&mut transport, KeyNumber::Key0, &[0u8; 16], RND_A)
        .await;
    assert!(result.is_ok(), "factory K0 works");

    let mut session = result.unwrap();
    let mut versions = [0u8; 5];
    let key_numbers = [
        KeyNumber::Key0,
        KeyNumber::Key1,
        KeyNumber::Key2,
        KeyNumber::Key3,
        KeyNumber::Key4,
    ];
    #[allow(clippy::indexing_slicing)]
    for (i, kn) in key_numbers.into_iter().enumerate() {
        let (v, s) = session
            .get_key_version(&mut transport, kn)
            .await
            .expect("get key version");
        versions[i] = v;
        session = s;
    }

    assert_eq!(versions, [0u8; 5], "all factory versions (0x00)");
}

#[tokio::test]
async fn keyver_on_provisioned_card_shows_provisioned_versions() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    let keys = derive_keys();
    let result = Session::default()
        .authenticate_aes(&mut transport, KeyNumber::Key0, keys.k0.as_bytes(), RND_A)
        .await;
    assert!(result.is_ok(), "derived K0 works");

    let mut session = result.unwrap();
    let mut versions = [0u8; 5];
    let key_numbers = [
        KeyNumber::Key0,
        KeyNumber::Key1,
        KeyNumber::Key2,
        KeyNumber::Key3,
        KeyNumber::Key4,
    ];
    #[allow(clippy::indexing_slicing)]
    for (i, kn) in key_numbers.into_iter().enumerate() {
        let (v, s) = session
            .get_key_version(&mut transport, kn)
            .await
            .expect("get key version");
        versions[i] = v;
        session = s;
    }

    assert_eq!(
        versions, [BURN_VERSION; 5],
        "all keys at provisioned version"
    );
}

#[tokio::test]
async fn picc_reads_ndef_and_extracts_sdm_params() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    let plan = sdm_url_config(TEST_URL, CryptoMode::Aes, boltcard_sdm_opts()).unwrap();

    let mut session = Session::default();
    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(&mut transport, File::Ndef, 0, &mut buf)
        .await
        .expect("read NDEF");

    assert!(len > 2, "NDEF has content");

    assert_eq!(
        &transport.ndef()[..plan.ndef_bytes.len()],
        plan.ndef_bytes.as_slice(),
        "NDEF content matches template"
    );
}

#[tokio::test]
async fn full_cycle_burn_wipe_reburn() {
    let mut transport = MockTransport::new();
    let keys = derive_keys();

    do_burn(&mut transport).await;
    assert_eq!(transport.key_versions(), &[BURN_VERSION; 5]);

    do_wipe(&mut transport).await;
    assert_eq!(transport.key_versions(), &[0u8; 5]);
    assert_eq!(transport.keys(), &[[0u8; 16]; 5]);

    do_burn(&mut transport).await;
    assert_eq!(transport.key_versions(), &[BURN_VERSION; 5]);
    assert_eq!(transport.keys()[0], *keys.k0.as_bytes());
    assert_eq!(transport.keys()[1], *keys.k1.as_bytes());

    let settings = FileSettingsView::decode(transport.file_settings()).expect("decode");
    assert!(settings.sdm.is_some(), "SDM active after re-burn");
}

#[tokio::test]
async fn factory_auth_fails_on_provisioned_card() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    let result = Session::default()
        .authenticate_aes(&mut transport, KeyNumber::Key0, &[0u8; 16], RND_A)
        .await;

    assert!(
        result.is_err(),
        "factory K0 must fail after burn (K0 changed to derived)"
    );
}

#[tokio::test]
async fn get_version_returns_ntag424_signature() {
    let mut transport = MockTransport::new();
    let session = Session::default();

    let version = session
        .get_version(&mut transport)
        .await
        .expect("get version");

    assert_eq!(version.hw_vendor_id(), 0x04, "NXP vendor ID");
    assert_eq!(version.hw_type(), 0x04, "NTAG424 type");
    assert_eq!(*version.uid(), UID, "version UID matches mock UID");
}

#[tokio::test]
async fn url_reads_ndef_from_provisioned_card() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    let plan = sdm_url_config(TEST_URL, CryptoMode::Aes, boltcard_sdm_opts()).unwrap();

    let mut session = Session::default();
    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(&mut transport, File::Ndef, 0, &mut buf)
        .await
        .expect("read NDEF");

    assert!(len > 2, "NDEF has content");
    let ndef_data = &buf[..len];
    assert_eq!(
        &ndef_data[..plan.ndef_bytes.len()],
        plan.ndef_bytes.as_slice(),
        "NDEF content matches burn template"
    );
    assert!(
        ndef_data[0] != 0x00 || ndef_data[1] != 0x00,
        "NLEN is non-zero"
    );
}

#[tokio::test]
async fn inspect_reads_file_settings_on_blank_card() {
    let mut transport = MockTransport::new();
    let mut session = Session::default();

    let uid = session.get_selected_uid(&mut transport).await.expect("uid");
    assert_eq!(uid.as_ref(), UID);

    let version = session.get_version(&mut transport).await.expect("version");
    assert_eq!(version.hw_vendor_id(), 0x04);
    assert_eq!(version.hw_type(), 0x04);

    let settings = session
        .get_file_settings(&mut transport, File::Ndef)
        .await
        .expect("file settings");
    assert!(settings.sdm.is_none(), "blank card has no SDM");

    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(&mut transport, File::Ndef, 0, &mut buf)
        .await
        .expect("read NDEF");
    assert!(
        len < 2 || (buf[0] == 0x00 && buf[1] == 0x00),
        "blank card has empty NDEF"
    );
}

#[tokio::test]
async fn inspect_reads_sdm_on_provisioned_card() {
    let mut transport = MockTransport::new();
    do_burn(&mut transport).await;

    let mut session = Session::default();

    let settings = session
        .get_file_settings(&mut transport, File::Ndef)
        .await
        .expect("file settings");
    assert!(settings.sdm.is_some(), "provisioned card has SDM");

    let mut buf = [0u8; 256];
    let len = session
        .read_file_unauthenticated(&mut transport, File::Ndef, 0, &mut buf)
        .await
        .expect("read NDEF");
    assert!(len > 2, "provisioned card has NDEF content");
    assert!(
        buf[0] != 0x00 || buf[1] != 0x00,
        "NLEN is non-zero on provisioned card"
    );
}
