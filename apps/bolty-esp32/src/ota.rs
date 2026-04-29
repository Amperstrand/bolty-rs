use core::fmt;
use core::time::Duration;
use std::io::{self, Read};

use embedded_svc::http::client::Client as HttpClient;
use esp_idf_svc::{
    http::client::{Configuration as HttpClientConfig, EspHttpConnection},
    ota::{EspOta, EspOtaUpdate},
    sys::EspError,
};
use log::info;

const OTA_CHUNK_SIZE: usize = 4096;
const OTA_PROGRESS_STEP: usize = 64 * 1024;

#[derive(Debug)]
pub enum OtaError {
    Esp(EspError),
    Http(io::Error),
    InvalidStatus(u16),
    EmptyImage,
}

impl fmt::Display for OtaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Esp(err) => write!(f, "{err}"),
            Self::Http(err) => write!(f, "http: {err}"),
            Self::InvalidStatus(status) => write!(f, "http status {status}"),
            Self::EmptyImage => f.write_str("empty firmware image"),
        }
    }
}

impl From<EspError> for OtaError {
    fn from(value: EspError) -> Self {
        Self::Esp(value)
    }
}

impl From<io::Error> for OtaError {
    fn from(value: io::Error) -> Self {
        Self::Http(value)
    }
}

pub struct OtaUpdater;

impl OtaUpdater {
    pub fn update(url: &str) -> Result<(), OtaError> {
        info!("starting ota update from {url}");

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
        let total = Self::download_to_partition(&mut response, &mut update)?;
        if total == 0 {
            return Err(OtaError::EmptyImage);
        }

        info!("ota image written: {total} bytes");
        update.complete()?;
        info!("ota complete, reboot requested");

        Ok(())
    }

    fn download_to_partition(
        response: &mut impl Read,
        update: &mut EspOtaUpdate<'_>,
    ) -> Result<usize, OtaError> {
        let mut buffer = [0u8; OTA_CHUNK_SIZE];
        let mut total = 0usize;
        let mut next_progress = OTA_PROGRESS_STEP;

        loop {
            let read = response.read(&mut buffer)?;
            if read == 0 {
                break;
            }

            update.write(&buffer[..read])?;
            total = total.saturating_add(read);

            while total >= next_progress {
                info!("ota progress: {} KB", next_progress / 1024);
                next_progress = next_progress.saturating_add(OTA_PROGRESS_STEP);
            }
        }

        Ok(total)
    }
}
