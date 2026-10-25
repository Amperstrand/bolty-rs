//! board-nucula frontend (issue #115): ESP32-C3 + PN7160 NCI reader.
//!
//! The nucula board runs the PN7160 NFC controller over I2C (NCI address
//! 0x28, SDA=GPIO4 / SCL=GPIO5 / IRQ=GPIO6 / VEN=GPIO7 — the bench-proven
//! geometry in `pn7160_nci::board::NUCULA`, ccid-firmware-rs #149 P2). The
//! ISO-DEP activation lives inside the NFCC, so unlike the MFRC522 boards
//! there is no iso14443-session layer here: `bolty_pn7160::Pn7160Transport`
//! implements `ntag424::Transport` directly and `bolty-ntag`'s generic
//! workflows drive the card.
//!
//! Scope (v1): serial console with reader bring-up, card poll/UID and an
//! unauthenticated safe-inspect — the bench proof that the frontend works
//! with a bolt card on the antenna. Burn/wipe/keys and NVS staging remain
//! M5-board territory until the service layer unifies over
//! `ntag424::Transport` (the console here deliberately stays small so that
//! unification has one consumer to converge on, not two to refactor).
//!
//! The console below is a private minimal copy of the M5 firmware's
//! `SerialConsole` (raw stdio FDs, non-blocking read) rather than a shared
//! extraction: the original lives as a private submodule of the MFRC522
//! firmware module, and hoisting it would touch the M5 path for no
//! functional gain in this PR. The line FRAMING, however, is shared:
//! `console_framing::LineAssembler` gives this console the same 512-byte
//! cap and drain-through-newline hostile-line guarantee as the M5 arm
//! (#204; the old local gate silently truncated overlong lines).

use core::fmt::Write as _;

#[cfg(feature = "wifi")]
use bolty_core::config::{WifiPasswordString, WifiSsidString};
use bolty_pn7160::{BusPins, EspPn7160Transport, NUCULA, Pn7160Driver, Pn7160Transport};
use esp_idf_hal::{delay::FreeRtos, peripherals::Peripherals};
use esp_idf_svc::log::EspLogger;
#[cfg(feature = "wifi")]
use esp_idf_svc::nvs::{EspDefaultNvs, EspDefaultNvsPartition, EspNvs};
use heapless::String;

#[cfg(feature = "ota-server")]
use crate::ota_server;
#[cfg(feature = "wifi")]
use crate::wifi::WifiManager;

use crate::block_on;
use crate::console_framing::{LineAssembler, LineEvent, MAX_LINE_LEN};

const BOARD_NAME: &str = "nucula (ESP32-C3 + PN7160)";
const BUILD_EPOCH: &str = env!("BOLTY_BUILD_EPOCH");
const SERIAL_FD_IN: i32 = 0;
const SERIAL_FD_OUT: i32 = 1;
const MAIN_LOOP_DELAY_MS: u32 = 10;
/// Credential namespace on the default NVS partition. Distinct from the
/// wifi driver's own `nvs.net80211` namespace (esp-idf-svc internal) —
/// both live on the same partition via clones of the one shared handle.
#[cfg(feature = "wifi")]
const NVS_NAMESPACE: &str = "boltnv";

/// Reader stack: `EspPn7160Transport` (I2C + IRQ + VEN) under the NCI
/// driver, wrapped in the `ntag424::Transport` bridge.
type Reader = Pn7160Transport<EspPn7160Transport>;

/// Wifi + OTA-seat state (feature `wifi`/`ota-server`): the bench
/// recovery door — with the OTA server up, every future image (bolty or
/// otherwise) can be pushed over the seat without serial.
#[cfg(feature = "wifi")]
struct Network {
    manager: Option<WifiManager>,
    /// Credential store, opened ONCE (read-write — bolty #144) from the
    /// shared partition handle and reused for every save/load (bolty
    /// #143: never re-`take()` the default partition).
    creds: Option<EspDefaultNvs>,
    #[cfg(feature = "ota-server")]
    ota_spawned: bool,
}

#[cfg(feature = "wifi")]
impl Network {
    fn new(modem: esp_idf_hal::modem::Modem<'static>, partition: &EspDefaultNvsPartition) -> Self {
        let manager = match WifiManager::new(modem, partition.clone()) {
            Ok(manager) => Some(manager),
            Err(err) => {
                log::warn!("wifi manager init failed: {err:?}");
                None
            }
        };
        // Read-write is load-bearing: `EspNvs::new(..., false)` opens
        // NVS_READONLY and every `set_blob` fails (bolty #144) — the
        // `wifi` command then reports success while storing nothing.
        let creds = match EspNvs::new(partition.clone(), NVS_NAMESPACE, true) {
            Ok(nvs) => Some(nvs),
            Err(err) => {
                log::warn!("nvs: credential namespace open failed: {err}");
                None
            }
        };
        Self {
            manager,
            creds,
            #[cfg(feature = "ota-server")]
            ota_spawned: false,
        }
    }

    /// No-partition fallback (bolty #143): wifi manager and credential
    /// store both unavailable — console stays up, `wifi` reports
    /// "manager unavailable" honestly instead of silently no-oping.
    fn degraded() -> Self {
        Self {
            manager: None,
            creds: None,
            #[cfg(feature = "ota-server")]
            ota_spawned: false,
        }
    }

    /// Connect with the given credentials, persist them, and bring up
    /// the OTA server once the station has an address.
    fn connect(&mut self, console: &mut Console, ssid: &str, password: &str) {
        let Some(manager) = self.manager.as_mut() else {
            console.fail("wifi manager unavailable");
            return;
        };
        let (Ok(ssid_str), Ok(pass_str)) = (
            WifiSsidString::try_from(ssid),
            WifiPasswordString::try_from(password),
        ) else {
            console.fail("ssid too long (max 32) or password too long (max 64)");
            return;
        };
        match manager.connect(&ssid_str, &pass_str) {
            Ok(()) => {
                // Surface persistence failures (bolty #144): the OTA
                // recovery door is only real if the creds survive the
                // reboot — a silent no-op here was the original bug.
                // Heapless per the #193 discipline (no format!() on
                // this target).
                if let Err(err) = self.save_wifi_creds(&ssid_str, &pass_str) {
                    log::warn!("nvs: credential save failed: {err}");
                    let mut msg = String::<96>::new();
                    let _ = write!(msg, "wifi connected but creds NOT stored: {err}");
                    console.fail(msg.as_str());
                }
                self.report(console, true);
            }
            Err(err) => console.fail(&format!("wifi connect failed: {err:?}")),
        }
    }

    /// Boot-time autoconnect from persisted credentials.
    fn autoconnect(&mut self, console: &mut Console) {
        let Some((ssid, password)) = self.load_wifi_creds() else {
            console.line("wifi: no stored credentials (use: wifi <ssid> <pass>)");
            return;
        };
        self.connect(console, ssid.as_str(), password.as_str());
    }

    /// Persist credentials (namespace `boltnv`); a truncated or missing
    /// pair is treated as absent on load. Both blobs commit on write
    /// (`EspNvs::set_blob` commits internally).
    fn save_wifi_creds(
        &self,
        ssid: &WifiSsidString,
        password: &WifiPasswordString,
    ) -> Result<(), esp_idf_sys::EspError> {
        let nvs = self
            .creds
            .as_ref()
            .ok_or(esp_idf_sys::EspError::from_infallible::<
                { esp_idf_sys::ESP_ERR_INVALID_STATE },
            >())?;
        nvs.set_blob(bolty_core::wifi_creds::KEY_SSID, ssid.as_bytes())?;
        nvs.set_blob(bolty_core::wifi_creds::KEY_PASS, password.as_bytes())?;
        Ok(())
    }

    fn load_wifi_creds(&self) -> Option<(WifiSsidString, WifiPasswordString)> {
        let nvs = self.creds.as_ref()?;
        let mut ssid_buf = [0u8; 32];
        let mut pass_buf = [0u8; 64];
        let ssid = nvs
            .get_blob(bolty_core::wifi_creds::KEY_SSID, &mut ssid_buf)
            .ok()??;
        let password = nvs
            .get_blob(bolty_core::wifi_creds::KEY_PASS, &mut pass_buf)
            .ok()??;
        bolty_core::wifi_creds::decode_creds_pair(Some(ssid), Some(password))
    }

    fn report(&mut self, console: &mut Console, verbose: bool) {
        let Some(manager) = self.manager.as_ref() else {
            console.line("wifi: manager unavailable");
            return;
        };
        match manager.ip() {
            Some(ip) => {
                console.ok(&format!("wifi: connected ip={ip}"));
                #[cfg(feature = "ota-server")]
                {
                    if !self.ota_spawned {
                        ota_server::spawn();
                        self.ota_spawned = true;
                        if verbose {
                            console.line("ota: server listening on :3232");
                        }
                    }
                }
            }
            None => console.fail("wifi: no ip (not connected)"),
        }
    }
}

#[cfg(not(feature = "wifi"))]
struct Network;

#[cfg(not(feature = "wifi"))]
impl Network {
    fn new() -> Self {
        Self
    }
    fn autoconnect(&mut self, _console: &mut Console) {}
}

pub fn main() {
    esp_idf_sys::link_patches();
    esp_idf_hal::sys::link_patches();
    EspLogger::initialize_default();

    let peripherals = match Peripherals::take() {
        Ok(peripherals) => peripherals,
        Err(_) => {
            // No console yet (the console needs this driver — see below):
            // the ROM console still mirrors logs, so this is visible.
            log::error!("peripherals already taken; halting");
            return;
        }
    };

    // Claim the native USB_SERIAL_JTAG peripheral from the ROM boot
    // console FIRST (bring-up finding 2026-10-23): the ROM owns it at
    // boot and provides TX-only mirroring — host console INPUT stalls at
    // the USB level until the driver is installed and re-arms RX, and
    // the driver's read API must not be called before installation
    // (Console::new drains RX — ordering caused a boot crash). Same
    // recipe as ccid-firmware-rs's C3 console (pn7160_ccid.rs). The
    // handle is intentionally leaked: it must outlive the console loop.
    {
        use esp_idf_hal::usb_serial::{UsbSerialDriver, config::Config as UsbConfig};
        match UsbSerialDriver::new(
            peripherals.usb_serial,
            peripherals.pins.gpio18,
            peripherals.pins.gpio19,
            &UsbConfig::new().rx_buffer_size(1024).tx_buffer_size(1024),
        ) {
            Ok(driver) => core::mem::forget(driver),
            Err(err) => log::error!("USB console driver claim failed: {err:?}"),
        }
    }

    let mut console = Console::new();
    console.line("[BOOT] bolty nucula frontend (issue #115)");
    console.ok_fmt(&["[BOOT] board=", BOARD_NAME, " built=", BUILD_EPOCH]);

    // Wifi modem + NVS partition go to the network stack before the NFC
    // block claims its pins (Peripherals::take is single-shot; the split
    // is by field). The default NVS partition is taken exactly ONCE
    // (bolty #143) — `EspDefaultNvsPartition::take()` is a global
    // singleton, so every later take() fails; the wifi driver and the
    // credential store share clones of this one Arc-backed handle.
    #[cfg(feature = "wifi")]
    let mut network = match esp_idf_svc::nvs::EspDefaultNvsPartition::take() {
        Ok(partition) => Network::new(peripherals.modem, &partition),
        Err(err) => {
            log::error!("nvs: default partition unavailable: {err}");
            Network::degraded()
        }
    };
    #[cfg(not(feature = "wifi"))]
    let mut network = Network::new();

    // Bench-proven bring-up order (ccid #149 P1, verdict B): I2C bus first,
    // then the VEN power cycle, probe inside the post-VEN ACK window, then
    // the NCI ladder (CORE_RESET..RF_DISCOVER) and ISO-DEP power-on. With a
    // card already on the antenna this activates it in one shot.
    let bus_pins = BusPins {
        i2c0: peripherals.i2c0,
        sda: peripherals.pins.gpio4,
        scl: peripherals.pins.gpio5,
        irq: peripherals.pins.gpio6,
        ven: peripherals.pins.gpio7,
    };
    // #145: a cardless boot must keep the INITIALIZED reader — the old
    // activate-only path dropped the transport on a no-card power-on,
    // leaving every later command "nfc unavailable" until a reboot.
    // The command paths re-run power_on() on the kept reader, so an
    // inserted card activates on the next poll/uid/inspect.
    let mut reader: Option<Reader> =
        match EspPn7160Transport::bringup_config_order(NUCULA, bus_pins) {
            Ok(transport) => match Pn7160Transport::new_initialized(Pn7160Driver::new(transport)) {
                Ok(mut reader) => match reader.power_on() {
                    Ok(()) => {
                        console.ok("PN7160 reader up (NCI ladder + ISO-DEP power-on)");
                        Some(reader)
                    }
                    Err(err) => {
                        log::warn!("PN7160 no card at boot (reader kept): {err:?}");
                        console.line("PN7160 up, no card at boot (kept — insert and run nfc)");
                        Some(reader)
                    }
                },
                Err(err) => {
                    log::error!("PN7160 NCI init failed: {err:?}");
                    console.fail("PN7160 NCI init failed (see log)");
                    None
                }
            },
            Err(err) => {
                log::error!("PN7160 I2C bring-up failed: {err:?}");
                console.fail("PN7160 I2C bring-up failed (see log)");
                console.fail("console continues without NFC (check VEN/IRQ wiring)");
                None
            }
        };

    let mut assembler = LineAssembler::<MAX_LINE_LEN>::new();
    network.autoconnect(&mut console);
    loop {
        while let Some(byte) = console.read_byte_nonblocking() {
            match assembler.feed(byte) {
                Some(LineEvent::Overflow) => {
                    // Issue #204: fail once and drain through the next
                    // newline. The old `line.len() < MAX_LINE_LEN` gate
                    // silently truncated and dispatched the prefix.
                    console.fail("command too long");
                }
                Some(LineEvent::Line(text)) => {
                    let handled = handle_line(text, reader.as_mut(), &mut network, &mut console);
                    if !handled {
                        console.ok_fmt(&["unknown command: ", text]);
                    }
                }
                None => {}
            }
        }
        FreeRtos::delay_ms(MAIN_LOOP_DELAY_MS);
    }
}

/// Dispatch one console line. Returns false for unknown commands (so the
/// caller can echo) and true for everything recognized, including failures.
fn handle_line(
    input: &str,
    reader: Option<&mut Reader>,
    network: &mut Network,
    console: &mut Console,
) -> bool {
    let command = input.trim();
    if command.is_empty() {
        return true;
    }
    let (head, rest) = match command.split_once(' ') {
        Some((head, rest)) => (head, Some(rest)),
        None => (command, None),
    };

    match head.to_ascii_lowercase().as_str() {
        "help" | "?" => {
            console.line("commands: help | ver | status | poll | uid | inspect | wifi | ip");
            true
        }
        "ver" => {
            console.line(&format!(
                "fw=bolty-esp32 board={BOARD_NAME} built={BUILD_EPOCH}"
            ));
            true
        }
        "status" => {
            match reader {
                Some(reader) => {
                    let uid = if reader.session_active() {
                        uid_hex(reader.uid())
                    } else {
                        String::new()
                    };
                    console.line(&format!(
                        "nfc=ok session={} uid={}",
                        if reader.session_active() {
                            "active"
                        } else {
                            "idle"
                        },
                        uid.as_str()
                    ));
                }
                None => console.line("nfc=missing (bring-up failed at boot)"),
            }
            let _ = rest;
            true
        }
        "poll" => {
            match reader {
                Some(reader) => match reader.power_on() {
                    Ok(()) => {
                        console.ok(&format!(
                            "card up: uid={} atr_len={}",
                            uid_hex(reader.uid()),
                            reader.atr().len()
                        ));
                    }
                    Err(err) => console.fail(&format!("no card / power-on failed: {err:?}")),
                },
                None => console.fail("nfc unavailable"),
            }
            true
        }
        "uid" => {
            match reader {
                Some(reader) => {
                    if !reader.session_active() && reader.power_on().is_err() {
                        console.fail("no card on antenna");
                    } else {
                        console.ok(&format!("uid={}", uid_hex(reader.uid())));
                    }
                }
                None => console.fail("nfc unavailable"),
            }
            true
        }
        "inspect" => {
            match reader {
                Some(reader) => {
                    if !reader.session_active() && reader.power_on().is_err() {
                        console.fail("no card on antenna");
                    } else {
                        match block_on(bolty_ntag::safe_inspect(reader, None, None)) {
                            Ok(result) => {
                                // Across-activation SDM liveness: the real card
                                // latches a fresh SDM mirror per RF ACTIVATION,
                                // not per read (relay-bench-proven 2026-10-25:
                                // identical p= within one activation, ticking
                                // p= across activations) — so a second inspect
                                // after a forced re-activation is the honest
                                // key-free liveness probe. The within-session
                                // sdm_mirroring field stays authoritative for
                                // Off/Unknown.
                                let across = if reader.power_on().is_ok() {
                                    block_on(bolty_ntag::safe_inspect(reader, None, None)).ok()
                                } else {
                                    None
                                };
                                // HEAPLESS (crash fix 2026-10-23: the coredump
                                // backtrace lands HERE — format!() exhausted the
                                // heap while WiFi + PN7160 + console held it;
                                // every console output on this RAM-tight C3
                                // goes through heapless String<N>).
                                let mut out = String::<384>::new();
                                let _ = write!(
                                    out,
                                    "uid={} ndef_bytes={}",
                                    uid_hex(&result.uid),
                                    result.ndef_bytes.as_ref().map_or(0, Vec::len)
                                );
                                console.line(out.as_str());
                                let mut sdm = String::<128>::new();
                                let label = match result.sdm_mirroring {
                                    bolty_ntag::SdmMirroring::Off => "off",
                                    bolty_ntag::SdmMirroring::Unknown => "unknown",
                                    _ => match (
                                        &result.ndef_bytes,
                                        across.as_ref().and_then(|a| a.ndef_bytes.as_ref()),
                                    ) {
                                        // fresh mirror served after re-activation
                                        (Some(first), Some(second)) if first != second => "live",
                                        (Some(_), Some(_)) => "static",
                                        // second probe failed: fall back to the
                                        // within-session assessment rather than
                                        // guessing.
                                        _ => match result.sdm_mirroring {
                                            bolty_ntag::SdmMirroring::Live => "live",
                                            _ => "static",
                                        },
                                    },
                                };
                                let _ = write!(sdm, "sdm={label}");
                                console.line(sdm.as_str());
                            }
                            Err(err) => console.fail(&format!("inspect failed: {err:?}")),
                        }
                    }
                }
                None => console.fail("nfc unavailable"),
            }
            true
        }
        "wifi" => {
            let Some(rest) = rest else {
                console.fail("usage: wifi <ssid> <password>");
                return true;
            };
            let Some((ssid, password)) = rest.split_once(' ') else {
                console.fail("usage: wifi <ssid> <password>");
                return true;
            };
            #[cfg(feature = "wifi")]
            network.connect(console, ssid.trim(), password.trim());
            #[cfg(not(feature = "wifi"))]
            {
                let _ = network;
                console.fail("wifi not compiled into this build");
            }
            true
        }
        "ip" => {
            #[cfg(feature = "wifi")]
            network.report(console, true);
            #[cfg(not(feature = "wifi"))]
            {
                let _ = network;
                console.fail("wifi not compiled into this build");
            }
            true
        }
        _ => {
            let _ = rest;
            false
        }
    }
}

fn uid_hex(uid: &[u8]) -> String<32> {
    let mut out = String::new();
    for (i, byte) in uid.iter().enumerate() {
        if i > 0 {
            let _ = out.push(':');
        }
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// Minimal stdio console (see module docs for why this is not shared with
/// the M5 firmware): non-blocking stdin, blocking newline-framed stdout.
struct Console;

impl Console {
    fn new() -> Self {
        // No fcntl(O_NONBLOCK) on fd 0 anymore: RX goes through the
        // usb_serial_jtag driver directly (see read_byte_nonblocking) and
        // the VFS console fd must stay untouched. Drain stale bytes from
        // boot/download mode so the first command isn't corrupted by
        // leftover flasher handshake data.
        let console = Self;
        console.flush_rx();
        console
    }

    fn flush_rx(&self) {
        let mut byte = 0u8;
        loop {
            let n = unsafe {
                esp_idf_sys::usb_serial_jtag_read_bytes((&mut byte as *mut u8).cast(), 1, 0)
            };
            if n != 1 {
                break;
            }
        }
    }

    fn read_byte_nonblocking(&mut self) -> Option<u8> {
        // RX via the usb_serial_jtag DRIVER API, never read(2) on fd 0:
        // the VFS non-blocking console-read path asserts in IDF
        // (usb_serial_jtag_vfs.c "c != NONE", bring-up 2026-10-23) once
        // UsbSerialDriver owns the peripheral. ccid's console reads this
        // way too. ticks=0 => non-blocking.
        let mut byte = 0u8;
        let n =
            unsafe { esp_idf_sys::usb_serial_jtag_read_bytes((&mut byte as *mut u8).cast(), 1, 0) };
        if n == 1 { Some(byte) } else { None }
    }

    fn line(&mut self, line: &str) {
        self.write_all(line.as_bytes());
        self.write_all(b"\r\n");
    }

    /// Format directly into a heapless buffer — NEVER format!() into
    /// console output on this target (the heap is ~143KB and WiFi/NFC/
    /// console share it; format!() allocates on that heap — coredump
    /// crash 2026-10-23 at firmware_nucula.rs:361).
    fn ok_fmt(&mut self, parts: &[&str]) {
        let mut out = String::<384>::new();
        for p in parts {
            if out.push_str(p).is_err() {
                break;
            }
        }
        self.ok(out.as_str());
    }

    fn ok(&mut self, message: &str) {
        let mut out = String::<384>::new();
        let _ = write!(out, "[OK] {message}");
        self.line(out.as_str());
    }

    fn fail(&mut self, message: &str) {
        let mut out = String::<384>::new();
        let _ = write!(out, "[FAIL] {message}");
        self.line(out.as_str());
    }

    fn write_all(&mut self, bytes: &[u8]) {
        let mut written = 0usize;
        while written < bytes.len() {
            let rc = unsafe {
                esp_idf_sys::write(
                    SERIAL_FD_OUT,
                    bytes[written..].as_ptr().cast(),
                    bytes.len() - written,
                )
            };
            if rc <= 0 {
                log::warn!("serial write failed: rc={rc}");
                break;
            }
            written += rc as usize;
        }
    }
}
