#![no_std]

use ntag424::{
    File, KeyNumber, NonMasterKeyNumber, Session, SessionError, Transport, Uid,
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, sdm_url_config},
    types::file_settings::CryptoMode,
};

pub const FACTORY_KEY: [u8; 16] = [0u8; 16];
pub const FACTORY_KEY_VERSION: u8 = 0x00;

pub type KeySet = [[u8; 16]; 5];

pub fn derive_keys(master_key: &[u8; 16], uid: &[u8; 7], system_id: &[u8]) -> KeySet {
    [
        diversify_ntag424(master_key, uid, KeyNumber::Key0, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key1, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key2, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key3, system_id),
        diversify_ntag424(master_key, uid, KeyNumber::Key4, system_id),
    ]
}

#[derive(Debug)]
pub struct BurnParams<'a> {
    pub lnurl: &'a str,
    pub keys: KeySet,
    pub key_version: u8,
}

#[derive(Debug)]
pub struct BurnResult {
    pub uid: [u8; 7],
}

#[derive(Debug)]
pub struct WipeResult {
    pub uid: [u8; 7],
}

#[derive(Debug)]
pub enum Error<T: core::error::Error + core::fmt::Debug> {
    Transport(T),
    SdmUrl(ntag424::sdm::SdmUrlError),
    Session(SessionError<T>),
}

impl<T: core::error::Error + core::fmt::Debug> From<SessionError<T>> for Error<T> {
    fn from(e: SessionError<T>) -> Self {
        Error::Session(e)
    }
}

impl<T: core::error::Error + core::fmt::Debug> From<ntag424::sdm::SdmUrlError> for Error<T> {
    fn from(e: ntag424::sdm::SdmUrlError) -> Self {
        Error::SdmUrl(e)
    }
}

fn uid_to_fixed(uid: &Uid) -> [u8; 7] {
    match uid {
        Uid::Fixed(f) => *f,
        Uid::Random(_) => [0u8; 7],
    }
}

pub async fn read_uid<T: Transport>(transport: &mut T) -> Result<[u8; 7], Error<T::Error>> {
    let uid = Session::default().get_selected_uid(transport).await?;
    Ok(uid_to_fixed(&uid))
}

pub async fn burn<T: Transport>(
    transport: &mut T,
    params: &BurnParams<'_>,
    rnd_a: [u8; 16],
) -> Result<BurnResult, Error<T::Error>> {
    let plan = sdm_url_config(params.lnurl, CryptoMode::Aes, SdmUrlOptions::new())?;

    let mut session = Session::default();

    let uid = session.get_selected_uid(transport).await?;
    let uid_fixed = uid_to_fixed(&uid);

    session
        .write_file_unauthenticated(transport, File::Ndef, 0, &plan.ndef_bytes)
        .await?;

    let session = session
        .authenticate_aes(transport, KeyNumber::Key0, &FACTORY_KEY, rnd_a)
        .await?;

    let (settings, session) = session.get_file_settings(transport, File::Ndef).await?;
    let update = settings.into_update().with_sdm(plan.sdm_settings);
    let session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await?;

    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key1,
            &params.keys[1],
            params.key_version,
            &FACTORY_KEY,
        )
        .await?;
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key2,
            &params.keys[2],
            params.key_version,
            &FACTORY_KEY,
        )
        .await?;
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key3,
            &params.keys[3],
            params.key_version,
            &FACTORY_KEY,
        )
        .await?;
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key4,
            &params.keys[4],
            params.key_version,
            &FACTORY_KEY,
        )
        .await?;

    let _session = session
        .change_master_key(transport, &params.keys[0], params.key_version)
        .await?;

    Ok(BurnResult { uid: uid_fixed })
}

pub async fn wipe<T: Transport>(
    transport: &mut T,
    keys: &KeySet,
    rnd_a: [u8; 16],
) -> Result<WipeResult, Error<T::Error>> {
    let session = Session::default();

    let uid = session.get_selected_uid(transport).await?;
    let uid_fixed = uid_to_fixed(&uid);

    let session = session
        .authenticate_aes(transport, KeyNumber::Key0, &keys[0], rnd_a)
        .await?;

    let (settings, session) = session.get_file_settings(transport, File::Ndef).await?;
    let update = settings.into_update();
    let mut session = session
        .change_file_settings(transport, File::Ndef, &update)
        .await?;

    let mut ndef_buf = [0u8; 256];
    let bytes_read = session
        .read_file_plain(transport, File::Ndef, 0, 0, &mut ndef_buf)
        .await?;
    for b in &mut ndef_buf[..bytes_read] {
        *b = 0;
    }
    session
        .write_file_plain(transport, File::Ndef, 0, &ndef_buf[..bytes_read])
        .await?;

    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key1,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys[1],
        )
        .await?;
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key2,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys[2],
        )
        .await?;
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key3,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys[3],
        )
        .await?;
    let session = session
        .change_key(
            transport,
            NonMasterKeyNumber::Key4,
            &FACTORY_KEY,
            FACTORY_KEY_VERSION,
            &keys[4],
        )
        .await?;

    let _session = session
        .change_master_key(transport, &FACTORY_KEY, FACTORY_KEY_VERSION)
        .await?;

    Ok(WipeResult { uid: uid_fixed })
}

pub async fn check_key_versions<T: Transport>(
    transport: &mut T,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<[u8; 5], Error<T::Error>> {
    let session = Session::default()
        .authenticate_aes(transport, KeyNumber::Key0, key, rnd_a)
        .await?;

    let key_numbers = [
        KeyNumber::Key0,
        KeyNumber::Key1,
        KeyNumber::Key2,
        KeyNumber::Key3,
        KeyNumber::Key4,
    ];
    let mut versions = [0u8; 5];
    let mut session = session;
    for (i, kn) in key_numbers.into_iter().enumerate() {
        let (v, s) = session.get_key_version(transport, kn).await?;
        versions[i] = v;
        session = s;
    }

    Ok(versions)
}
