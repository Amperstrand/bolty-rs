use std::fmt;

use bolty_ntag::{Response, Transport};

/// PCSC-based transport for communicating with NTAG424 cards.
///
/// Connects to the first available PCSC reader with a card present
/// and implements the `ntag424::Transport` trait.
pub struct PcscTransport {
    card: pcsc::Card,
    reader_name: String,
    protocol: pcsc::Protocols,
}

#[derive(Debug)]
pub enum PcscError {
    NoReaders,
    NoCardInReader(String),
    Pcsc(pcsc::Error),
    Transmit(String),
}

impl fmt::Display for PcscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcscError::NoReaders => write!(f, "no PCSC readers found"),
            PcscError::NoCardInReader(name) => {
                write!(f, "no card present in reader: {name}")
            }
            PcscError::Pcsc(e) => write!(f, "PCSC error: {e}"),
            PcscError::Transmit(msg) => write!(f, "transmit error: {msg}"),
        }
    }
}

impl std::error::Error for PcscError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PcscError::Pcsc(e) => Some(e),
            _ => None,
        }
    }
}

impl From<pcsc::Error> for PcscError {
    fn from(e: pcsc::Error) -> Self {
        PcscError::Pcsc(e)
    }
}

impl PcscTransport {
    /// Connect to the first available reader with a card present.
    pub fn connect() -> Result<Self, PcscError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let readers = ctx.list_readers_owned()?;

        let reader_cstr = readers
            .iter()
            .find(|r| r.to_str().map(|s| s.contains("PICC")).unwrap_or(false))
            .or_else(|| {
                readers
                    .iter()
                    .find(|r| r.to_str().map(|s| !s.contains("SAM")).unwrap_or(false))
            })
            .or_else(|| readers.first())
            .ok_or(PcscError::NoReaders)?;
        let reader_name = reader_cstr.to_str().unwrap_or("(unknown)").to_string();

        let (card, protocol) = ctx
            .connect(reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::T1)
            .map(|c| (c, pcsc::Protocols::T1))
            .or_else(|_| {
                ctx.connect(reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::RAW)
                    .map(|c| (c, pcsc::Protocols::RAW))
            })
            .or_else(|_| {
                ctx.connect(reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::T0)
                    .map(|c| (c, pcsc::Protocols::T0))
            })
            .map_err(|e| match e {
                pcsc::Error::NoSmartcard => PcscError::NoCardInReader(reader_name.clone()),
                other => PcscError::Pcsc(other),
            })?;

        Ok(Self {
            card,
            reader_name,
            protocol,
        })
    }

    /// Get the reader name.
    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    /// Power-cycle the card using SCARD_UNPOWER_CARD.
    ///
    /// This unpowers the card (removes RF field), then repowers it.
    /// On NTAG424, this resets the volatile SeqFailCtr, clearing auth delay.
    /// Does NOT reset TotFailCtr (non-volatile EEPROM counter).
    pub fn power_cycle(&mut self) -> Result<(), PcscError> {
        self.card
            .reconnect(
                pcsc::ShareMode::Shared,
                self.protocol,
                pcsc::Disposition::UnpowerCard,
            )
            .map_err(PcscError::from)
    }
}

impl Transport for PcscTransport {
    type Error = PcscError;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Vec<u8>>, Self::Error> {
        let mut recv_buf = [0u8; 261]; // Max APDU response size
        let rapdu = self
            .card
            .transmit(apdu, &mut recv_buf)
            .map_err(|e| PcscError::Transmit(format!("{e}")))?;

        if rapdu.len() < 2 {
            return Err(PcscError::Transmit(format!(
                "response too short ({} bytes)",
                rapdu.len()
            )));
        }

        // SAFETY: rapdu.len() >= 2 is checked above.
        #[allow(clippy::indexing_slicing)]
        let data = rapdu[..rapdu.len() - 2].to_vec();
        #[allow(clippy::indexing_slicing)]
        let sw1 = rapdu[rapdu.len() - 2];
        #[allow(clippy::indexing_slicing)]
        let sw2 = rapdu[rapdu.len() - 1];

        Ok(Response { data, sw1, sw2 })
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        // GET DATA (INS CA) for UID — standard PCSC GET DATA APDU
        let apdu = [0xff, 0xca, 0x00, 0x00, 0x00];
        let response = self.transmit(&apdu).await?;

        // PCSC pseudo-APDU 0xFF CA is handled by the reader firmware, not the
        // card. On some readers (e.g. ACS ACR1252), this corrupts the ISO
        // 14443-4 protocol state — subsequent native NTAG424 APDUs fail with
        // "card reset". Reconnect to restore a clean card session.
        let _ = self.card.reconnect(
            pcsc::ShareMode::Shared,
            self.protocol,
            pcsc::Disposition::ResetCard,
        );

        if response.sw1 != 0x90 || response.sw2 != 0x00 {
            return Err(PcscError::Transmit(format!(
                "GET UID failed: SW={:02X}{:02X}",
                response.sw1, response.sw2
            )));
        }

        Ok(response.data)
    }
}
