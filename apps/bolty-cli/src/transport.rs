use std::ffi::CString;
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
    #[allow(dead_code)]
    ctx: pcsc::Context,
}

#[derive(Debug)]
pub enum PcscError {
    NoReaders,
    NoCardInReader(String),
    PinUnmatched(String),
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
            PcscError::PinUnmatched(want) => write!(
                f,
                "reader pin '{want}' matches no PCSC reader (see `bolty-cli readers`) \
                 — refusing to silently fall back to auto-selection for a \
                 mutation-capable tool"
            ),
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

/// Virtual-reader detector: vpcd/virtual readers shadow the ACR1252's real
/// PICC interface in name-based matching and must never be auto-selected.
fn is_virtual(name: &str) -> bool {
    // Case-insensitive: real bench reader names have appeared as
    // "vpcd" AND "vPICC" (the j3r180 table-sim, 2026-10-23) — a
    // case-sensitive match let the latter slip the filter and hijack
    // auto-selection (it contains "PICC").
    let lower = name.to_ascii_lowercase();
    lower.contains("virtual") || lower.contains("vpcd") || lower.contains("vpicc")
}

/// Pure reader-selection policy, unit-tested without pcsc:
///
/// - An explicit pin (CLI `--reader` or `BOLTY_READER`) MUST match exactly
///   one candidate substring-wise — a set-but-unmatched pin is a LOUD
///   error, never a silent fall-back to auto-selection (this tool burns
///   and wipes cards; a typo must not retarget it). A pin may select a
///   virtual reader — explicit user intent beats the auto-exclusion.
/// - Auto-selection considers only non-virtual readers: prefer a "PICC"
///   interface, then any non-"SAM" slot, then any candidate. Virtual-only
///   benches error NoReaders instead of silently grabbing a vpcd.
pub fn select_reader<'a>(names: &[&'a str], pin: Option<&str>) -> Result<&'a str, PcscError> {
    if let Some(want) = pin {
        return names
            .iter()
            .copied()
            .find(|n| n.contains(want))
            .ok_or_else(|| PcscError::PinUnmatched(want.to_string()));
    }
    let candidates: Vec<&str> = names.iter().copied().filter(|n| !is_virtual(n)).collect();
    candidates
        .iter()
        .copied()
        .find(|n| n.contains("PICC"))
        .or_else(|| candidates.iter().copied().find(|n| !n.contains("SAM")))
        .or_else(|| candidates.first().copied())
        .ok_or(PcscError::NoReaders)
}

/// Reader inventory row for the `readers` command.
pub struct ReaderStatus {
    pub name: String,
    pub virtual_reader: bool,
    pub card_present: Option<bool>,
}

/// List all readers with a best-effort card-presence probe (connect
/// attempt per reader; errors map to None = unknown).
pub fn list_readers_with_presence() -> Result<Vec<ReaderStatus>, PcscError> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let readers = ctx.list_readers_owned()?;
    let mut out = Vec::new();
    for reader in &readers {
        let name = reader.to_str().unwrap_or("(unknown)").to_string();
        let presence = ctx
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::T1)
            .or_else(|_| ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::RAW))
            .or_else(|_| ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::T0))
            .map(|_| true)
            .or_else(|e| {
                if matches!(e, pcsc::Error::NoSmartcard) {
                    Ok(false)
                } else {
                    Err(e)
                }
            })
            .ok();
        out.push(ReaderStatus {
            virtual_reader: is_virtual(&name),
            name,
            card_present: presence,
        });
    }
    Ok(out)
}

impl PcscTransport {
    /// Connect with an explicit reader pin (`--reader`), falling back to
    /// the `BOLTY_READER` env pin (#121), then auto-selection.
    pub fn connect_with(pin: Option<&str>) -> Result<Self, PcscError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let readers = ctx.list_readers_owned()?;
        let names: Vec<&str> = readers
            .iter()
            .map(|r| r.to_str().unwrap_or("(unknown)"))
            .collect();
        let effective_pin = pin
            .map(|p| p.to_string())
            .or_else(|| std::env::var("BOLTY_READER").ok());
        let selected = select_reader(&names, effective_pin.as_deref())?;
        let reader_cstr = CString::new(selected).unwrap_or_default();
        let reader_name = selected.to_string();

        let (card, protocol) = ctx
            .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::T1)
            .map(|c| (c, pcsc::Protocols::T1))
            .or_else(|_| {
                ctx.connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::RAW)
                    .map(|c| (c, pcsc::Protocols::RAW))
            })
            .or_else(|_| {
                ctx.connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::T0)
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
            ctx,
        })
    }

    /// Get the reader name.
    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    /// Power-cycle the card to reset SeqFailCtr (clears auth delay).
    ///
    /// Uses SCardDisconnect(SCARD_UNPOWER_CARD) + SCardConnect() which forces
    /// a full new RF field activation. SCardReconnect(SCARD_UNPOWER_CARD) does
    /// NOT work on ACS ACR1252 — it keeps the card in the same ISO 14443 session.
    #[allow(dead_code)]
    pub fn power_cycle(self) -> Result<Self, PcscError> {
        let reader_cstr = std::ffi::CString::new(self.reader_name.as_str()).unwrap_or_default();
        let ctx = self.ctx;

        self.card
            .disconnect(pcsc::Disposition::UnpowerCard)
            .map_err(|(_, e)| PcscError::from(e))?;

        std::thread::sleep(std::time::Duration::from_secs(2));

        let (card, protocol) = ctx
            .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::T1)
            .map(|c| (c, pcsc::Protocols::T1))
            .or_else(|_| {
                ctx.connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::RAW)
                    .map(|c| (c, pcsc::Protocols::RAW))
            })
            .or_else(|_| {
                ctx.connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::T0)
                    .map(|c| (c, pcsc::Protocols::T0))
            })?;

        Ok(Self {
            card,
            reader_name: reader_cstr.to_string_lossy().to_string(),
            protocol,
            ctx,
        })
    }
}

fn hex_preview(d: &[u8]) -> String {
    d.iter()
        .take(24)
        .map(|b| format!("{b:02X}"))
        .collect::<String>()
}

impl Transport for PcscTransport {
    type Error = PcscError;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Vec<u8>>, Self::Error> {
        if std::env::var_os("BOLTY_APDU_LOG").is_some() {
            eprintln!(
                "APDU> {}",
                apdu.iter().map(|b| format!("{b:02X}")).collect::<String>()
            );
        }
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

        if std::env::var_os("BOLTY_APDU_LOG").is_some() {
            eprintln!("<SW {sw1:02X}{sw2:02X} ({})", hex_preview(&data));
        }
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
        // A reconnect re-activates the card, and javacard NTAG424 emulators
        // (unlike real NTAG424 tags) do NOT implicitly re-select the NDEF
        // application at activation — native 0x90 commands then land on the
        // wrong app and fail 6E00. Re-select explicitly; idempotent on real
        // tags. (Bench-proven on the J3R180 ntag424-applet, 2026-10-26.)
        let select_ndef = [
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
        ];
        let _ = self
            .card
            .transmit(&select_ndef, &mut [0u8; 261])
            .map_err(|e| PcscError::Transmit(format!("NDEF re-select after reconnect: {e}")))?;

        if response.sw1 != 0x90 || response.sw2 != 0x00 {
            return Err(PcscError::Transmit(format!(
                "GET UID failed: SW={:02X}{:02X}",
                response.sw1, response.sw2
            )));
        }

        Ok(response.data)
    }
}

#[cfg(test)]
mod select_tests {
    use super::PcscError;
    use super::select_reader;

    const BENCH: &[&str] = &[
        "ACS ACR1252 Dual Reader [ACR1252 Dual Reader SAM] 02 00",
        "ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 03 00",
        "Nucula CCID via broker 01 00",
        "Virtual PICC boltcard vpcd 00 00",
        "Virtual PICC boltcard vpcd 00 01",
    ];

    #[test]
    fn auto_prefers_picc_and_skips_virtuals() {
        assert_eq!(
            select_reader(BENCH, None).unwrap(),
            "ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 03 00"
        );
    }

    #[test]
    fn pin_selects_by_substring() {
        assert_eq!(
            select_reader(BENCH, Some("Nucula")).unwrap(),
            "Nucula CCID via broker 01 00"
        );
    }

    #[test]
    fn pin_may_explicitly_target_a_virtual_reader() {
        assert_eq!(
            select_reader(BENCH, Some("vpcd 00 01")).unwrap(),
            "Virtual PICC boltcard vpcd 00 01"
        );
    }

    #[test]
    fn unmatched_pin_is_a_loud_error_not_a_fallback() {
        assert!(matches!(
            select_reader(BENCH, Some("typo-reader")),
            Err(PcscError::PinUnmatched(w)) if w == "typo-reader"
        ));
    }

    #[test]
    fn virtual_only_bench_errors_instead_of_grabbing_vpcd() {
        assert!(matches!(
            select_reader(&["Virtual PICC boltcard vpcd 00 00"], None),
            Err(PcscError::NoReaders)
        ));
    }

    #[test]
    fn sam_only_real_readers_still_selectable() {
        assert_eq!(
            select_reader(&["Some Reader SAM 00 00", "Other Reader 01 00"], None).unwrap(),
            "Other Reader 01 00"
        );
    }

    #[test]
    fn empty_bench_is_no_readers() {
        assert!(matches!(
            select_reader(&[], None),
            Err(PcscError::NoReaders)
        ));
    }
}
