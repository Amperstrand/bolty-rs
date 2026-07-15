use core::fmt;
use core::time::Duration;

use embedded_svc::http::client::Client as HttpClient;
use esp_idf_svc::{
    http::client::{Configuration as HttpClientConfig, EspHttpConnection},
    ota::EspOta,
    sys::EspError,
};
use log::info;

const OTA_CHUNK_SIZE: usize = 4096;
const OTA_PROGRESS_STEP: usize = 64 * 1024;

#[derive(Debug)]
pub enum OtaError {
    Esp(EspError),
    Http(String),
    InvalidStatus(u16),
    EmptyImage,
    SignatureUnprovisioned,
    SignatureInvalid,
}

impl fmt::Display for OtaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Esp(err) => write!(f, "{err}"),
            Self::Http(msg) => write!(f, "http: {msg}"),
            Self::InvalidStatus(status) => write!(f, "http status {status}"),
            Self::EmptyImage => f.write_str("empty firmware image"),
            Self::SignatureUnprovisioned => {
                f.write_str("OTA signing key not provisioned (run 'provision-ota-key')")
            }
            Self::SignatureInvalid => f.write_str("firmware signature verification FAILED"),
        }
    }
}

impl From<EspError> for OtaError {
    fn from(value: EspError) -> Self {
        Self::Esp(value)
    }
}

impl From<esp_idf_hal::io::EspIOError> for OtaError {
    fn from(value: esp_idf_hal::io::EspIOError) -> Self {
        Self::Http(format!("{value}"))
    }
}

pub struct OtaUpdater;

impl OtaUpdater {
    pub fn update(url: &str, signature_hex: &str) -> Result<(), OtaError> {
        let signing_key =
            crate::firmware::nvs::load_ota_pubkey().ok_or(OtaError::SignatureUnprovisioned)?;
        let expected_sig = decode_hex_signature(signature_hex).ok_or(OtaError::SignatureInvalid)?;

        info!("starting signed ota update from {url}");

        let connection = EspHttpConnection::new(&HttpClientConfig {
            timeout: Some(Duration::from_secs(120)),
            buffer_size: Some(8192),
            ..Default::default()
        })?;
        let mut client = HttpClient::wrap(connection);
        let request = client.request(
            embedded_svc::http::Method::Get,
            url,
            &[("Accept", "application/octet-stream")],
        )?;
        let mut response = request.submit()?;

        if response.status() != 200 {
            return Err(OtaError::InvalidStatus(response.status()));
        }

        let mut ota = EspOta::new()?;
        let mut update = ota.initiate_update()?;

        let mut buffer = [0u8; OTA_CHUNK_SIZE];
        let mut total = 0usize;
        let mut next_progress = OTA_PROGRESS_STEP;
        let mut sha_ctx: esp_idf_sys::mbedtls_sha256_context = unsafe { core::mem::zeroed() };

        unsafe {
            esp_idf_sys::mbedtls_sha256_init(&mut sha_ctx);
            esp_idf_sys::mbedtls_sha256_starts(&mut sha_ctx, 0);
        }

        loop {
            let read: usize = response
                .read(&mut buffer)
                .map_err(|e| OtaError::Http(format!("{e:?}")))?;
            if read == 0 {
                break;
            }

            update.write(&buffer[..read])?;

            unsafe {
                esp_idf_sys::mbedtls_sha256_update(&mut sha_ctx, buffer[..read].as_ptr(), read);
            }

            total = total.saturating_add(read);

            while total >= next_progress {
                info!("ota progress: {} KB", next_progress / 1024);
                next_progress = next_progress.saturating_add(OTA_PROGRESS_STEP);
            }
        }

        let mut hash = [0u8; 32];
        unsafe {
            esp_idf_sys::mbedtls_sha256_finish(&mut sha_ctx, hash.as_mut_ptr());
            esp_idf_sys::mbedtls_sha256_free(&mut sha_ctx);
        }

        if total == 0 {
            return Err(OtaError::EmptyImage);
        }

        info!("ota image written: {total} bytes");

        verify_ed25519_signature(&signing_key, &hash, &expected_sig)?;

        info!("ota signature VERIFIED — committing");
        update.complete()?;
        info!("ota complete, reboot requested");

        Ok(())
    }
}

fn verify_ed25519_signature(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), OtaError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| OtaError::SignatureInvalid)?;
    let sig = Signature::from_bytes(signature);

    vk.verify(message, &sig)
        .map_err(|_| OtaError::SignatureInvalid)
}

fn decode_hex_signature(hex: &str) -> Option<[u8; 64]> {
    bolty_core::util::decode_hex(hex).ok()
}
