#[cfg(target_arch = "xtensa")]
use core::future::Future;
#[cfg(target_arch = "xtensa")]
use core::pin::pin;
#[cfg(target_arch = "xtensa")]
use core::task::{Context, Poll, Waker};

#[cfg(target_arch = "xtensa")]
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("future yielded unexpectedly"),
    }
}

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "wifi")]
mod wifi;

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "rest")]
mod rest;

#[cfg(target_arch = "xtensa")]
#[cfg(feature = "ota")]
mod ota;

#[cfg(all(target_arch = "xtensa", feature = "display-st7789"))]
mod display;

#[cfg(all(
    target_arch = "xtensa",
    feature = "board-m5atom",
    feature = "board-m5stick"
))]
compile_error!("Enable exactly one board feature: `board-m5atom` or `board-m5stick`.");

#[cfg(all(
    target_arch = "xtensa",
    not(any(feature = "board-m5atom", feature = "board-m5stick"))
))]
compile_error!("Enable one board feature: `board-m5atom` or `board-m5stick`.");

#[cfg(all(target_arch = "xtensa", not(feature = "nfc-mfrc522")))]
compile_error!("The current firmware requires the `nfc-mfrc522` feature.");

#[cfg(all(
    target_arch = "xtensa",
    feature = "led-matrix",
    not(feature = "board-m5atom")
))]
compile_error!("`led-matrix` is only supported on `board-m5atom`.");

#[cfg(all(
    target_arch = "xtensa",
    feature = "display-st7789",
    not(feature = "board-m5stick")
))]
compile_error!("`display-st7789` is only supported on `board-m5stick`.");

#[cfg(target_arch = "xtensa")]
mod firmware {
    use core::fmt::Write as _;
    use std::{
        sync::{Arc, Mutex},
        vec::Vec,
    };

    use bolty_core::{
        assessment::{CardAssessment, CardState},
        commands::{Command, CommandError, parse_command},
        config::{BoltyConfig, ErrorString, IssuerConfig, LnurlString},
        issuer::assess_card,
        secret::CardKeys,
        service::{BoltyService, ServiceStatus, WorkflowResult},
        workflow::dispatch_command,
    };
    use bolty_mfrc522::{DEFAULT_I2C_ADDRESS, Mfrc522Transceiver, Mfrc522Transport};
    #[cfg(feature = "ota")]
    use esp_idf_hal::reset::restart;
    use esp_idf_hal::{
        delay::FreeRtos,
        i2c::{I2cConfig, I2cDriver},
        peripherals::Peripherals,
        units::FromValueType,
    };
    use esp_idf_sys as _;
    use heapless::String;
    use log::info;
    use ntag424::{CommMode, FileSettingsView, KeyNumber, types::file_settings::Access};

    use crate::block_on;
    #[cfg(feature = "display-st7789")]
    use crate::display;
    #[cfg(feature = "ota")]
    use crate::ota::OtaUpdater;
    #[cfg(feature = "rest")]
    use crate::rest::{RestBoltyService, RestServer};
    #[cfg(feature = "wifi")]
    use crate::wifi::{WifiError, WifiManager};

    #[cfg(not(feature = "wifi"))]
    struct WifiManager;

    #[cfg(feature = "board-m5atom")]
    const BOARD_NAME: &str = "M5Atom";
    #[cfg(feature = "board-m5stick")]
    const BOARD_NAME: &str = "M5StickC Plus";

    const RND_A: [u8; 16] = [0u8; 16];
    const I2C_BAUDRATE_HZ: u32 = 400_000;
    const MAX_LINE_LEN: usize = 512;
    const SERIAL_FD_IN: i32 = 0;
    const SERIAL_FD_OUT: i32 = 1;
    const CARD_POLL_INTERVAL_MS: u64 = 500;
    const MAIN_LOOP_DELAY_MS: u32 = 10;
    #[cfg(feature = "rest")]
    const REST_PORT: u16 = 80;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DiagnoseState {
        Blank,
        Provisioned,
        AuthDelay,
        Inconsistent,
    }

    struct PiccResult {
        inspect: bolty_ntag::SafeInspectResult,
        keys_loaded: bool,
        keys_confirmed: bool,
        uid_match: Option<bool>,
    }

    struct DiagnoseResult {
        inspect: bolty_ntag::SafeInspectResult,
        zero_key_attempted: bool,
        zero_key_auth_ok: bool,
        state: DiagnoseState,
    }

    pub fn main() {
        esp_idf_sys::link_patches();
        esp_idf_hal::sys::link_patches();
        esp_idf_svc::log::EspLogger::initialize_default();

        let peripherals = Peripherals::take().unwrap_or_else(|_| {
            log::error!("FATAL: peripherals already taken");
            loop {}
        });

        #[cfg(feature = "led-matrix")]
        neopixel_off(peripherals.pins.gpio27);

        #[cfg(feature = "wifi")]
        let modem = peripherals.modem;

        #[cfg(feature = "display-st7789")]
        {
            let result = unsafe {
                display::init(
                    peripherals.i2c1,
                    peripherals.spi2,
                    peripherals.pins.gpio21,
                    peripherals.pins.gpio22,
                    peripherals.pins.gpio13,
                    peripherals.pins.gpio15,
                    peripherals.pins.gpio5,
                    peripherals.pins.gpio23,
                    peripherals.pins.gpio18,
                    peripherals.pins.gpio27,
                    BOARD_NAME,
                )
            };
            if let Err(e) = result {
                log::error!("Display init failed: {e}");
            }
        }

        #[cfg(feature = "board-m5atom")]
        let (i2c_sda, i2c_scl) = (peripherals.pins.gpio26, peripherals.pins.gpio32);
        #[cfg(feature = "board-m5stick")]
        let (i2c_sda, i2c_scl) = (peripherals.pins.gpio32, peripherals.pins.gpio33);

        FreeRtos::delay_ms(50);

        let mut i2c = match I2cDriver::new(
            peripherals.i2c0,
            i2c_sda,
            i2c_scl,
            &I2cConfig::new().baudrate(I2C_BAUDRATE_HZ.Hz()),
        ) {
            Ok(i2c) => i2c,
            Err(e) => {
                log::error!("FATAL: I2C0 init failed: {e:?}");
                loop {}
            }
        };
        log::info!("I2C0 initialized ({BOARD_NAME}) @ {}Hz", I2C_BAUDRATE_HZ);

        let initial_i2c_scan = scan_i2c_bus(&mut i2c);
        let mfrc522_seen = initial_i2c_scan
            .iter()
            .any(|&address| address == DEFAULT_I2C_ADDRESS);

        let (xcvr, raw_i2c, nfc_ready) = if mfrc522_seen {
            match Mfrc522Transceiver::from_i2c(i2c, DEFAULT_I2C_ADDRESS) {
                Ok(xcvr) => {
                    log::info!("MFRC522 initialized at 0x{:02X}", DEFAULT_I2C_ADDRESS);
                    (Some(xcvr), None, true)
                }
                Err(e) => {
                    log::warn!("MFRC522 init failed, continuing without NFC: {e:?}");
                    (None, None, false)
                }
            }
        } else {
            log::warn!(
                "MFRC522 not detected at 0x{:02X}; continuing without NFC",
                DEFAULT_I2C_ADDRESS
            );
            (None, Some(i2c), false)
        };

        let mut serial = SerialConsole::new();
        let initial_config = BoltyConfig::default();
        let config = Arc::new(Mutex::new(initial_config.clone()));
        let service = Arc::new(Mutex::new(Esp32BoltyService::new(
            xcvr,
            raw_i2c,
            initial_i2c_scan,
            initial_config,
        )));

        #[cfg(feature = "display-st7789")]
        display::set_nfc_ready(nfc_ready);
        #[cfg(feature = "wifi")]
        let mut wifi_manager = match WifiManager::new(modem) {
            Ok(manager) => Some(manager),
            Err(err) => {
                info!("wifi init unavailable: {err}");
                None
            }
        };
        #[cfg(not(feature = "wifi"))]
        let mut wifi_manager: Option<WifiManager> = None;
        #[cfg(feature = "rest")]
        let mut rest_server = None;
        let mut line = String::<MAX_LINE_LEN>::new();
        let mut next_poll_at = millis();
        let mut card_announced = false;

        info!("=== Bolty Ready ===");
        print_boot_banner(&mut serial);

        #[cfg(feature = "display-st7789")]
        display::set_event("ready");

        loop {
            while let Some(byte) = serial.read_byte_nonblocking() {
                match byte {
                    b'\r' => {}
                    b'\n' => {
                        if !line.is_empty() {
                            handle_line(
                                &mut serial,
                                line.as_str(),
                                &service,
                                &config,
                                &mut wifi_manager,
                                #[cfg(feature = "rest")]
                                &mut rest_server,
                            );
                            line.clear();
                            card_announced = false;
                        }
                    }
                    _ => {
                        if line.push(byte as char).is_err() {
                            serial.fail("command too long");
                            line.clear();
                        }
                    }
                }
            }

            let now = millis();
            if now >= next_poll_at {
                poll_card(&mut serial, &service, &mut card_announced);
                next_poll_at = now.saturating_add(CARD_POLL_INTERVAL_MS);
            }

            FreeRtos::delay_ms(MAIN_LOOP_DELAY_MS);
        }
    }

    struct Esp32BoltyService<I2C>
    where
        I2C: embedded_hal::i2c::I2c,
    {
        transceiver: Option<Mfrc522Transceiver<I2C>>,
        raw_i2c: Option<I2C>,
        last_i2c_scan: Vec<u8>,
        current_config: BoltyConfig,
        keys: Option<CardKeys>,
        authenticated_key0: Option<[u8; 16]>,
        last_card: CardAssessment,
        status: ServiceStatus,
    }

    impl<I2C> Esp32BoltyService<I2C>
    where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        fn new(
            transceiver: Option<Mfrc522Transceiver<I2C>>,
            raw_i2c: Option<I2C>,
            last_i2c_scan: Vec<u8>,
            current_config: BoltyConfig,
        ) -> Self {
            let nfc_ready = transceiver.is_some();
            let mut service = Self {
                transceiver,
                raw_i2c,
                last_i2c_scan,
                current_config,
                keys: None,
                authenticated_key0: None,
                last_card: CardAssessment::default(),
                status: ServiceStatus {
                    last_uid: None,
                    nfc_ready,
                    lnurl: None,
                },
            };
            service.sync_config();
            service
        }

        fn sync_from(&mut self, config: &BoltyConfig) {
            self.current_config = config.clone();
            self.sync_config();
        }

        fn sync_config(&mut self) {
            self.status.lnurl = self.current_config.lnurl.clone();
            self.status.nfc_ready = self.transceiver.is_some();
            if self.keys.is_none() {
                self.keys = self.current_config.pending_keys.clone();
            }
        }

        fn nfc_available(&self) -> bool {
            self.transceiver.is_some()
        }

        fn i2c_scan(&mut self) -> Vec<u8> {
            if let Some(i2c) = self.raw_i2c.as_mut() {
                self.last_i2c_scan = scan_i2c_bus(i2c);
            }
            self.last_i2c_scan.clone()
        }

        fn activate_transport(&mut self) -> Result<Mfrc522Transport<'_, I2C>, WorkflowResult> {
            let Some(transceiver) = self.transceiver.as_mut() else {
                self.status.nfc_ready = false;
                self.last_card = CardAssessment::default();
                return Err(nfc_unavailable_result());
            };

            Mfrc522Transport::activate(transceiver).map_err(|_| {
                self.status.nfc_ready = true;
                self.last_card = CardAssessment::default();
                WorkflowResult::CardNotPresent
            })
        }

        fn inspect_with_key(&mut self, key: &[u8; 16]) -> Result<CardAssessment, WorkflowResult> {
            let mut transport = self.activate_transport()?;
            let uid = copy_uid7(transport.uid())
                .ok_or_else(|| workflow_error("unsupported uid length"))?;
            let key_versions = block_on(bolty_ntag::check_key_versions(&mut transport, key, RND_A))
                .map_err(|err| map_ntag_error(&err))?;

            let issuer = self
                .current_config
                .pending_issuer
                .as_ref()
                .map(|issuer_key| IssuerConfig {
                    name: self.current_config.issuer_name.clone(),
                    issuer_key: issuer_key.clone(),
                    ..IssuerConfig::default()
                });
            let issuers = issuer.as_ref().map(core::slice::from_ref).unwrap_or(&[]);

            let assessment = assess_card(&uid, key_versions, issuers);
            self.authenticated_key0 = Some(*key);
            self.last_card = assessment.clone();
            self.status.last_uid = Some(uid);
            self.status.nfc_ready = true;

            Ok(assessment)
        }

        fn current_burn_key(&self, uid: Option<[u8; 7]>) -> [u8; 16] {
            match (uid, self.status.last_uid, self.authenticated_key0) {
                (Some(current_uid), Some(last_uid), Some(key)) if current_uid == last_uid => key,
                _ => bolty_ntag::FACTORY_KEY,
            }
        }

        fn picc(&mut self) -> Result<PiccResult, WorkflowResult> {
            let keys = self.keys.clone();
            let keys_loaded = keys.is_some();
            let k1 = keys.as_ref().map(|keys| keys.k1.as_bytes());
            let k2 = keys.as_ref().map(|keys| keys.k2.as_bytes());
            let k0 = keys.as_ref().map(|keys| *keys.k0.as_bytes());

            let mut transport = self.activate_transport()?;
            let inspect = block_on(bolty_ntag::safe_inspect(&mut transport, k1, k2))
                .map_err(|err| map_ntag_error(&err))?;

            let uid_match = inspect
                .sdm_verification
                .as_ref()
                .and_then(|verification| verification.uid.map(|uid| uid == inspect.uid));
            let keys_confirmed = inspect.sdm_verification.is_some() && keys_loaded;

            self.status.last_uid = Some(inspect.uid);
            self.status.nfc_ready = true;
            self.last_card = CardAssessment {
                state: if keys_confirmed {
                    CardState::Provisioned(0)
                } else {
                    CardState::Unknown
                },
                present: true,
                uid: uid_storage_from_fixed(&inspect.uid),
                uid_len: 7,
                has_ndef: inspect.ndef_bytes.is_some(),
                ..CardAssessment::default()
            };

            if let Some(k0) = k0.filter(|_| keys_confirmed) {
                self.authenticated_key0 = Some(k0);
            }

            Ok(PiccResult {
                inspect,
                keys_loaded,
                keys_confirmed,
                uid_match,
            })
        }

        fn diagnose(&mut self) -> Result<DiagnoseResult, WorkflowResult> {
            let mut transport = self.activate_transport()?;
            let inspect = block_on(bolty_ntag::safe_inspect(&mut transport, None, None))
                .map_err(|err| map_ntag_error(&err))?;

            let factory_like = looks_factory_default(inspect.file_settings.as_ref());
            let mut zero_key_attempted = false;
            let mut zero_key_auth_ok = false;
            let mut state = if inspect
                .file_settings
                .as_ref()
                .and_then(|settings| settings.sdm)
                .is_some()
            {
                DiagnoseState::Provisioned
            } else {
                DiagnoseState::Inconsistent
            };

            if factory_like {
                zero_key_attempted = true;
                match block_on(ntag424::Session::default().authenticate_aes(
                    &mut transport,
                    KeyNumber::Key0,
                    &bolty_ntag::FACTORY_KEY,
                    RND_A,
                )) {
                    Ok(_) => {
                        zero_key_auth_ok = true;
                        state = DiagnoseState::Blank;
                    }
                    Err(ntag424::SessionError::ErrorResponse(
                        ntag424::types::ResponseStatus::AuthenticationDelay,
                    )) => {
                        state = DiagnoseState::AuthDelay;
                    }
                    Err(_) => {
                        state = DiagnoseState::Inconsistent;
                    }
                }
            } else if inspect.file_settings.is_some() || inspect.ndef_bytes.is_some() {
                state = DiagnoseState::Provisioned;
            }

            self.status.last_uid = Some(inspect.uid);
            self.status.nfc_ready = true;
            self.last_card = CardAssessment {
                state: match state {
                    DiagnoseState::Blank => CardState::Blank,
                    DiagnoseState::Provisioned => CardState::Provisioned(0),
                    DiagnoseState::AuthDelay | DiagnoseState::Inconsistent => CardState::Unknown,
                },
                present: true,
                uid: uid_storage_from_fixed(&inspect.uid),
                uid_len: 7,
                has_ndef: inspect.ndef_bytes.is_some(),
                zero_key_auth_ok,
                ..CardAssessment::default()
            };

            Ok(DiagnoseResult {
                inspect,
                zero_key_attempted,
                zero_key_auth_ok,
                state,
            })
        }
    }

    impl<I2C> BoltyService for Esp32BoltyService<I2C>
    where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        fn burn(&mut self, keys: &CardKeys, lnurl: &str) -> WorkflowResult {
            let key_version = self
                .current_config
                .pending_issuer
                .as_ref()
                .map(|_| IssuerConfig::default().key_version)
                .unwrap_or(IssuerConfig::default().key_version);

            // Must compute key before activate_transport() — borrow checker constraint.
            let current_key = self.current_burn_key(None);

            let mut transport = match self.activate_transport() {
                Ok(transport) => transport,
                Err(err) => return err,
            };

            let params = bolty_ntag::BurnParams {
                lnurl,
                keys: card_keys_to_keyset(keys),
                key_version,
                current_key,
            };

            match block_on(bolty_ntag::burn(&mut transport, &params, RND_A)) {
                Ok(result) => {
                    self.status.last_uid = Some(result.uid);
                    self.status.nfc_ready = true;
                    self.keys = Some(keys.clone());
                    self.authenticated_key0 = Some(*keys.k0.as_bytes());
                    self.current_config.pending_keys = Some(keys.clone());
                    self.current_config.lnurl = copy_lnurl(lnurl);
                    self.sync_config();
                    WorkflowResult::Success
                }
                Err(err) => map_ntag_error(&err),
            }
        }

        fn wipe(&mut self, expected_keys: Option<&CardKeys>) -> WorkflowResult {
            let Some(keys) = expected_keys else {
                return WorkflowResult::WipeRefused;
            };

            log::info!("wipe: k0={:02X?}", keys.k0.as_bytes());

            let mut transport = match self.activate_transport() {
                Ok(transport) => transport,
                Err(err) => return err,
            };

            match block_on(bolty_ntag::wipe(
                &mut transport,
                &card_keys_to_keyset(keys),
                RND_A,
            )) {
                Ok(result) => {
                    self.status.last_uid = Some(result.uid);
                    self.status.nfc_ready = true;
                    self.keys = None;
                    self.authenticated_key0 = Some(bolty_ntag::FACTORY_KEY);
                    self.last_card = CardAssessment {
                        state: CardState::Blank,
                        present: true,
                        uid: uid_storage_from_fixed(&result.uid),
                        uid_len: 7,
                        ..CardAssessment::default()
                    };
                    WorkflowResult::Success
                }
                Err(err) => map_ntag_error(&err),
            }
        }

        fn inspect(&mut self) -> Result<CardAssessment, WorkflowResult> {
            if let Some(keys) = self.keys.clone() {
                match self.inspect_with_key(keys.k0.as_bytes()) {
                    Ok(assessment) => return Ok(assessment),
                    Err(WorkflowResult::AuthFailed) | Err(WorkflowResult::CardNotPresent) => {}
                    Err(WorkflowResult::AuthDelay) => return Err(WorkflowResult::AuthDelay),
                    Err(err) => return Err(err),
                }
            }

            self.inspect_with_key(&bolty_ntag::FACTORY_KEY)
        }

        fn check_blank(&mut self) -> WorkflowResult {
            match self.inspect() {
                Ok(assessment) if assessment.state == CardState::Blank => WorkflowResult::Success,
                Ok(_) => workflow_error("card not blank"),
                Err(err) => err,
            }
        }

        fn get_status(&self) -> ServiceStatus {
            self.status.clone()
        }
    }

    #[cfg(feature = "rest")]
    impl<I2C> RestBoltyService for Esp32BoltyService<I2C>
    where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        fn sync_from(&mut self, config: &BoltyConfig) {
            Self::sync_from(self, config);
        }
    }

    struct SerialConsole;

    impl SerialConsole {
        fn new() -> Self {
            let rc = unsafe {
                esp_idf_sys::fcntl(
                    SERIAL_FD_IN,
                    esp_idf_sys::F_SETFL as i32,
                    esp_idf_sys::O_NONBLOCK as i32,
                )
            };
            if rc < 0 {
                log::warn!("failed to set stdin non-blocking: rc={rc}");
            }
            Self
        }

        fn read_byte_nonblocking(&mut self) -> Option<u8> {
            let mut byte = 0u8;
            let read = unsafe { esp_idf_sys::read(SERIAL_FD_IN, (&mut byte as *mut u8).cast(), 1) };
            if read == 1 { Some(byte) } else { None }
        }

        fn line(&mut self, line: &str) {
            self.write_all(line.as_bytes());
            self.write_all(b"\r\n");
        }

        fn ok(&mut self, message: &str) {
            let mut line = String::<300>::new();
            let _ = write!(line, "[OK] {message}");
            self.line(line.as_str());
        }

        fn fail(&mut self, message: &str) {
            let mut line = String::<300>::new();
            let _ = write!(line, "[FAIL] {message}");
            self.line(line.as_str());
        }

        fn card(&mut self, assessment: &CardAssessment) {
            let mut uid = String::<32>::new();
            if let Some(raw_uid) = assessment.uid.as_ref() {
                let _ = push_uid_hex(&mut uid, &raw_uid[..assessment.uid_len as usize]);
            }

            let mut line = String::<96>::new();
            let _ = write!(
                line,
                "[CARD] uid={} state={}",
                uid.as_str(),
                card_state_label(assessment.state)
            );
            self.line(line.as_str());
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
                    break;
                }
                written += rc as usize;
            }
        }
    }

    fn handle_line<I2C>(
        serial: &mut SerialConsole,
        line: &str,
        service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
        config: &Arc<Mutex<BoltyConfig>>,
        wifi_manager: &mut Option<WifiManager>,
        #[cfg(feature = "rest")] rest_server: &mut Option<RestServer<Esp32BoltyService<I2C>>>,
    ) where
        I2C: embedded_hal::i2c::I2c + Send + 'static,
        I2C::Error: core::fmt::Debug,
    {
        let command = match parse_command(line) {
            Ok(command) => command,
            Err(err) => {
                let message = command_error_message(err);
                serial.fail(message);
                set_display_fail(command_name_from_line(line), message);
                return;
            }
        };

        #[cfg(feature = "wifi")]
        match &command {
            Command::SetWifi { ssid, password } => {
                let Some(manager) = wifi_manager.as_mut() else {
                    serial.fail("wifi unavailable");
                    set_display_fail("wifi", "wifi unavailable");
                    return;
                };
                match manager.connect(ssid, password) {
                    Ok(()) => {
                        serial.ok("wifi connected");
                        set_display_ok("wifi", "wifi connected");
                        #[cfg(feature = "display-st7789")]
                        if let Some(ip) = wifi_ip_string() {
                            display::set_wifi(ip.as_str());
                        }
                        #[cfg(feature = "rest")]
                        {
                            if rest_server.is_none() {
                                match RestServer::start(
                                    REST_PORT,
                                    Arc::clone(config),
                                    Arc::clone(service),
                                ) {
                                    Ok(server) => {
                                        *rest_server = Some(server);
                                        serial.ok("rest server started");
                                        set_display_ok("wifi", "rest server started");
                                    }
                                    Err(err) => {
                                        let message = rest_error_message(&err);
                                        serial.fail(message.as_str());
                                        set_display_fail("wifi", message.as_str());
                                        return;
                                    }
                                }
                            }

                            match manager.advertise_http_service(REST_PORT) {
                                Ok(()) => {
                                    serial.ok("mdns bolty.local active");
                                    set_display_ok("wifi", "mdns bolty.local active");
                                }
                                Err(err) => {
                                    let message = wifi_error_message(&err);
                                    serial.fail(message.as_str());
                                    set_display_fail("wifi", message.as_str());
                                }
                            }
                        }
                    }
                    Err(err) => {
                        let message = wifi_error_message(&err);
                        serial.fail(message.as_str());
                        set_display_fail("wifi", message.as_str());
                    }
                }
                return;
            }
            Command::WifiOff => {
                let Some(manager) = wifi_manager.as_mut() else {
                    serial.fail("wifi unavailable");
                    set_display_fail("wifi off", "wifi unavailable");
                    return;
                };
                match manager.disconnect() {
                    Ok(()) => {
                        #[cfg(feature = "rest")]
                        if let Some(server) = rest_server.take() {
                            server.stop();
                        }
                        #[cfg(feature = "display-st7789")]
                        display::clear_wifi();
                        serial.ok("wifi disconnected");
                        set_display_ok("wifi off", "wifi disconnected");
                    }
                    Err(err) => {
                        let message = wifi_error_message(&err);
                        serial.fail(message.as_str());
                        set_display_fail("wifi off", message.as_str());
                    }
                }
                return;
            }
            #[cfg(feature = "ota")]
            Command::Ota { url } => {
                match OtaUpdater::update(url.as_str()) {
                    Ok(()) => {
                        serial.ok("rebooting");
                        set_display_ok("ota", "rebooting");
                        restart();
                    }
                    Err(err) => {
                        let mut message = String::<128>::new();
                        let _ = write!(message, "{err}");
                        serial.fail(message.as_str());
                        set_display_fail("ota", message.as_str());
                    }
                }
                return;
            }
            _ => {}
        }

        #[cfg(all(feature = "wifi", not(feature = "ota")))]
        if matches!(&command, Command::Ota { .. }) {
            serial.fail("ota feature disabled");
            set_display_fail("ota", "ota feature disabled");
            return;
        }

        #[cfg(not(feature = "wifi"))]
        if matches!(
            &command,
            Command::SetWifi { .. } | Command::WifiOff | Command::Ota { .. }
        ) {
            let _ = wifi_manager;
            serial.fail("wifi feature disabled");
            set_display_fail(command_name(&command), "wifi feature disabled");
            return;
        }

        let command_copy = command.clone();
        let mut config = match config.lock() {
            Ok(config) => config,
            Err(_) => {
                serial.fail("config unavailable");
                return;
            }
        };
        let mut service = match service.lock() {
            Ok(service) => service,
            Err(_) => {
                serial.fail("service unavailable");
                return;
            }
        };

        match &command {
            Command::I2cScan => {
                print_i2c_scan(serial, &mut service);
                return;
            }
            Command::Picc => {
                print_picc(serial, &mut service);
                return;
            }
            Command::Diagnose => {
                print_diagnose(serial, &mut service);
                return;
            }
            _ => {}
        }

        let result = dispatch_command(command, &mut *service, &mut config);
        service.sync_from(&config);

        match command_copy {
            Command::Help => {
                print_help(serial);
                serial.ok("help");
                set_display_ok("help", "help");
            }
            Command::Status => print_status(serial, &service),
            Command::Uid => print_uid(serial, &service),
            Command::Inspect => {
                let success = matches!(&result, WorkflowResult::Success);
                print_inspect(serial, &service, result);
                #[cfg(feature = "display-st7789")]
                if success {
                    display::set_event("inspect complete");
                }
            }
            _ => {
                let success = matches!(&result, WorkflowResult::Success);
                print_command_result(serial, &service, &command_copy, result);
                #[cfg(feature = "display-st7789")]
                if success {
                    match &command_copy {
                        Command::Burn => display::set_event("burn complete"),
                        Command::Wipe => display::set_event("wipe complete"),
                        Command::Check => display::set_event("card is blank"),
                        _ => {}
                    }
                }
            }
        }
    }

    fn print_boot_banner(serial: &mut SerialConsole) {
        serial.line("=== Bolty Ready ===");
        print_help(serial);
    }

    fn print_help(serial: &mut SerialConsole) {
        serial.line("Commands: help status uid i2cscan keys <k0..k4> issuer [hex] url <lnurl> burn wipe inspect picc diagnose check");
        #[cfg(feature = "wifi")]
        serial.line("WiFi: wifi <ssid> <password> | wifi off");
        #[cfg(feature = "ota")]
        serial.line("OTA: ota <url>");
    }

    fn print_i2c_scan<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
    where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        let found = service.i2c_scan();
        let mut line = String::<MAX_LINE_LEN>::new();
        let _ = line.push_str("i2cscan: found ");
        if found.is_empty() {
            let _ = line.push_str("none");
        } else {
            for (index, address) in found.iter().enumerate() {
                if index > 0 {
                    let _ = line.push_str(", ");
                }
                let _ = write!(line, "0x{address:02X}");
            }
        }
        serial.ok(line.as_str());
        set_display_ok("i2cscan", line.as_str());
    }

    fn print_picc<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
    where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        match service.picc() {
            Ok(result) => {
                let mut uid = String::<32>::new();
                let _ = push_uid_hex(&mut uid, &result.inspect.uid);
                let mut uid_line = String::<96>::new();
                let _ = write!(uid_line, "uid={}", uid.as_str());
                serial.ok(uid_line.as_str());

                match result.inspect.ndef_bytes.as_deref() {
                    Some(bytes) => {
                        let ascii = ndef_ascii(bytes);
                        let mut line = String::<MAX_LINE_LEN>::new();
                        let _ = write!(line, "ndef={}", ascii.as_str());
                        serial.line(line.as_str());
                    }
                    None => serial.line("ndef=unavailable"),
                }

                match result.inspect.sdm_verification.as_ref() {
                    Some(verification) => {
                        let mut line = String::<160>::new();
                        let read_ctr = match verification.read_ctr {
                            Some(read_ctr) => CounterDisplay::Value(read_ctr),
                            None => CounterDisplay::None,
                        };
                        let _ = write!(
                            line,
                            "sdm=ok uid_match={} read_ctr={}",
                            result.uid_match.unwrap_or(false),
                            read_ctr
                        );
                        serial.line(line.as_str());
                    }
                    None => serial.line("sdm=unverified"),
                }

                let mut line = String::<96>::new();
                let _ = write!(
                    line,
                    "keys_loaded={} keys_confirmed={}",
                    result.keys_loaded, result.keys_confirmed
                );
                serial.line(line.as_str());
                serial.ok("picc complete");
                set_display_ok("picc", "picc complete");
            }
            Err(err) => {
                set_display_workflow_result("picc", &err);
                print_workflow_result(serial, err);
            }
        }
    }

    fn print_diagnose<I2C>(serial: &mut SerialConsole, service: &mut Esp32BoltyService<I2C>)
    where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        match service.diagnose() {
            Ok(result) => {
                let mut uid = String::<32>::new();
                let _ = push_uid_hex(&mut uid, &result.inspect.uid);
                let mut line = String::<96>::new();
                let _ = write!(line, "uid={}", uid.as_str());
                serial.ok(line.as_str());

                if let Some(version) = result.inspect.version.as_ref() {
                    let mut version_line = String::<96>::new();
                    let _ = write!(
                        version_line,
                        "version=hw {}.{} sw {}.{}",
                        version.hw_major_version(),
                        version.hw_minor_version(),
                        version.sw_major_version(),
                        version.sw_minor_version()
                    );
                    serial.line(version_line.as_str());
                } else {
                    serial.line("version=unavailable");
                }

                let mut fs_line = String::<128>::new();
                let _ = write!(
                    fs_line,
                    "file_settings={} ndef={} zero_key_attempted={} zero_key_auth_ok={}",
                    result.inspect.file_settings.is_some(),
                    result.inspect.ndef_bytes.is_some(),
                    result.zero_key_attempted,
                    result.zero_key_auth_ok
                );
                serial.line(fs_line.as_str());

                let mut state_line = String::<64>::new();
                let _ = write!(
                    state_line,
                    "classification={}",
                    diagnose_state_label(result.state)
                );
                serial.line(state_line.as_str());
                serial.ok("diagnose complete");
                set_display_ok("diagnose", "diagnose complete");
            }
            Err(err) => {
                set_display_workflow_result("diagnose", &err);
                print_workflow_result(serial, err);
            }
        }
    }

    #[cfg(feature = "wifi")]
    fn wifi_error_message(error: &WifiError) -> String<128> {
        let mut out = String::<128>::new();
        let _ = write!(out, "{error}");
        out
    }

    #[cfg(feature = "rest")]
    fn rest_error_message(error: &esp_idf_sys::EspError) -> String<128> {
        let mut out = String::<128>::new();
        let _ = write!(out, "rest start failed: {error}");
        out
    }

    fn print_status<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
    where
        I2C: embedded_hal::i2c::I2c,
    {
        let status = service.get_status();
        let mut uid = String::<32>::new();
        if let Some(last_uid) = status.last_uid {
            let _ = push_uid_hex(&mut uid, &last_uid);
        }

        let mut line = String::<320>::new();
        let _ = write!(
            line,
            "nfc_ready={} uid={} lnurl={}",
            status.nfc_ready,
            if uid.is_empty() { "none" } else { uid.as_str() },
            status
                .lnurl
                .as_ref()
                .map(LnurlString::as_str)
                .unwrap_or("none")
        );
        serial.ok(line.as_str());
        set_display_ok("status", line.as_str());
    }

    fn print_uid<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
    where
        I2C: embedded_hal::i2c::I2c,
    {
        if let Some(last_uid) = service.get_status().last_uid {
            let mut uid = String::<32>::new();
            let _ = push_uid_hex(&mut uid, &last_uid);
            serial.ok(uid.as_str());
            set_display_ok("uid", uid.as_str());
        } else {
            serial.fail("no uid");
            set_display_fail("uid", "no uid");
        }
    }

    fn print_inspect<I2C>(
        serial: &mut SerialConsole,
        service: &Esp32BoltyService<I2C>,
        result: WorkflowResult,
    ) where
        I2C: embedded_hal::i2c::I2c,
    {
        match result {
            WorkflowResult::Success => {
                serial.card(&service.last_card);
                serial.ok("inspect complete");
                set_display_ok("inspect", "inspect complete");
            }
            other => {
                set_display_workflow_result("inspect", &other);
                print_workflow_result(serial, other);
            }
        }
    }

    fn print_command_result<I2C>(
        serial: &mut SerialConsole,
        service: &Esp32BoltyService<I2C>,
        command: &Command,
        result: WorkflowResult,
    ) where
        I2C: embedded_hal::i2c::I2c,
    {
        match (command, result) {
            (Command::Check, WorkflowResult::Success) => {
                serial.card(&service.last_card);
                serial.ok("card is blank");
                set_display_ok(command_name(command), "card is blank");
            }
            (Command::SetKeys(_), WorkflowResult::Success) => {
                serial.ok("keys staged");
                set_display_ok(command_name(command), "keys staged");
            }
            (Command::SetIssuer(_), WorkflowResult::Success) => {
                serial.ok("issuer staged");
                set_display_ok(command_name(command), "issuer staged");
            }
            (Command::SetUrl(_), WorkflowResult::Success) => {
                serial.ok("lnurl staged");
                set_display_ok(command_name(command), "lnurl staged");
            }
            (Command::Burn, WorkflowResult::Success) => {
                serial.ok("burn complete");
                set_display_ok(command_name(command), "burn complete");
            }
            (Command::Wipe, WorkflowResult::Success) => {
                serial.ok("wipe complete");
                set_display_ok(command_name(command), "wipe complete");
            }
            (_, other) => {
                set_display_workflow_result(command_name(command), &other);
                print_workflow_result(serial, other);
            }
        }
    }

    fn print_workflow_result(serial: &mut SerialConsole, result: WorkflowResult) {
        match result {
            WorkflowResult::Success => serial.ok("success"),
            WorkflowResult::CardNotPresent => serial.fail("card not present"),
            WorkflowResult::AuthFailed => serial.fail("authentication failed"),
            WorkflowResult::AuthDelay => {
                serial.fail("AUTH DELAY (0x91AD): Card authentication failure counter triggered.");
                serial.line("Remove card from reader field for several seconds and retry.");
                serial.line("Ensure you are using the correct key.");
            }
            WorkflowResult::WipeRefused => serial.fail("wipe refused"),
            WorkflowResult::Error(message) => serial.fail(message.as_str()),
        }
    }

    fn poll_card<I2C>(
        serial: &mut SerialConsole,
        service: &Arc<Mutex<Esp32BoltyService<I2C>>>,
        card_announced: &mut bool,
    ) where
        I2C: embedded_hal::i2c::I2c,
        I2C::Error: core::fmt::Debug,
    {
        let mut service = match service.lock() {
            Ok(service) => service,
            Err(_) => return,
        };

        if !service.nfc_available() {
            *card_announced = false;
            #[cfg(feature = "display-st7789")]
            display::clear_card();
            return;
        }

        match service.check_blank() {
            WorkflowResult::CardNotPresent => {
                *card_announced = false;
                #[cfg(feature = "display-st7789")]
                display::clear_card();
            }
            WorkflowResult::Success | WorkflowResult::Error(_) => {
                if !*card_announced && service.last_card.present {
                    serial.card(&service.last_card);
                    *card_announced = true;
                    #[cfg(feature = "display-st7789")]
                    {
                        let mut uid_hex = heapless::String::<16>::new();
                        if let Some(uid) = service.last_card.uid.as_ref() {
                            let _ = push_uid_hex(
                                &mut uid_hex,
                                &uid[..service.last_card.uid_len as usize],
                            );
                        }
                        display::set_card(
                            uid_hex.as_str(),
                            card_state_label(service.last_card.state),
                        );
                    }
                }
            }
            WorkflowResult::AuthFailed
            | WorkflowResult::AuthDelay
            | WorkflowResult::WipeRefused => {
                if !*card_announced && service.last_card.present {
                    serial.card(&service.last_card);
                    *card_announced = true;
                    #[cfg(feature = "display-st7789")]
                    {
                        let mut uid_hex = heapless::String::<16>::new();
                        if let Some(uid) = service.last_card.uid.as_ref() {
                            let _ = push_uid_hex(
                                &mut uid_hex,
                                &uid[..service.last_card.uid_len as usize],
                            );
                        }
                        display::set_card(
                            uid_hex.as_str(),
                            card_state_label(service.last_card.state),
                        );
                    }
                }
            }
        }
    }

    #[cfg(all(feature = "display-st7789", feature = "wifi"))]
    fn wifi_ip_string() -> Option<String<16>> {
        let key = b"WIFI_STA_DEF\0";
        let handle = unsafe { esp_idf_sys::esp_netif_get_handle_from_ifkey(key.as_ptr().cast()) };
        if handle.is_null() {
            return None;
        }

        let mut ip_info: esp_idf_sys::esp_netif_ip_info_t = Default::default();
        let rc = unsafe { esp_idf_sys::esp_netif_get_ip_info(handle, &mut ip_info) };
        if rc != 0 {
            return None;
        }

        let mut out = String::<16>::new();
        let [a, b, c, d] = ip_info.ip.addr.to_le_bytes();
        write!(out, "{a}.{b}.{c}.{d}").ok()?;
        Some(out)
    }

    fn command_error_message(error: CommandError) -> &'static str {
        match error {
            CommandError::UnknownCommand => "unknown command",
            CommandError::InvalidArgs => "invalid arguments",
            CommandError::MissingArgs => "missing arguments",
        }
    }

    fn command_name(command: &Command) -> &'static str {
        match command {
            Command::Help => "help",
            Command::Status => "status",
            Command::Uid => "uid",
            Command::I2cScan => "i2cscan",
            Command::SetKeys(_) => "keys",
            Command::SetIssuer(_) | Command::Issuer => "issuer",
            Command::SetUrl(_) => "url",
            Command::Burn => "burn",
            Command::Wipe => "wipe",
            Command::Ndef => "ndef",
            Command::Auth => "auth",
            Command::Ver => "ver",
            Command::KeyVer => "keyver",
            Command::Inspect => "inspect",
            Command::Picc => "picc",
            Command::Diagnose => "diagnose",
            Command::Check => "check",
            Command::DummyBurn => "dummyburn",
            Command::Reset => "reset",
            Command::DeriveKeys => "derivekeys",
            Command::SetWifi { .. } => "wifi",
            Command::WifiOff => "wifi off",
            Command::Ota { .. } => "ota",
        }
    }

    fn command_name_from_line(line: &str) -> &str {
        line.split_whitespace().next().unwrap_or("command")
    }

    fn set_display_ok(cmd_name: &str, message: &str) {
        set_display_result(cmd_name, "OK", message);
    }

    fn set_display_fail(cmd_name: &str, message: &str) {
        set_display_result(cmd_name, "FAIL", message);
    }

    fn set_display_result(cmd_name: &str, status: &str, message: &str) {
        #[cfg(feature = "display-st7789")]
        {
            let mut result = String::<64>::new();
            let _ = write!(result, "{status}: {message}");
            display::set_command_result(cmd_name, result.as_str());
        }

        #[cfg(not(feature = "display-st7789"))]
        let _ = (cmd_name, status, message);
    }

    fn set_display_workflow_result(cmd_name: &str, result: &WorkflowResult) {
        match result {
            WorkflowResult::Success => set_display_ok(cmd_name, "success"),
            WorkflowResult::CardNotPresent => set_display_fail(cmd_name, "card not present"),
            WorkflowResult::AuthFailed => set_display_fail(cmd_name, "authentication failed"),
            WorkflowResult::AuthDelay => set_display_fail(cmd_name, "auth delay"),
            WorkflowResult::WipeRefused => set_display_fail(cmd_name, "wipe refused"),
            WorkflowResult::Error(message) => set_display_fail(cmd_name, message.as_str()),
        }
    }

    fn workflow_error(message: &str) -> WorkflowResult {
        let mut out = ErrorString::new();
        if out.push_str(message).is_err() {
            let _ = out.push_str("workflow error");
        }
        WorkflowResult::Error(out)
    }

    fn nfc_unavailable_result() -> WorkflowResult {
        workflow_error("nfc unavailable")
    }

    fn workflow_error_debug<T: core::fmt::Debug>(error: &T) -> WorkflowResult {
        let mut out = ErrorString::new();
        if write!(out, "{error:?}").is_err() {
            let _ = out.push_str("debug fmt overflow");
        }
        WorkflowResult::Error(out)
    }

    fn map_ntag_error<T>(error: &bolty_ntag::Error<T>) -> WorkflowResult
    where
        T: core::error::Error + core::fmt::Debug,
    {
        match error {
            err if bolty_ntag::is_authentication_delay(err) => WorkflowResult::AuthDelay,
            bolty_ntag::Error::Session(ntag424::SessionError::ErrorResponse(status)) => {
                log::warn!("ntag424 auth error: {:?}", status);
                WorkflowResult::AuthFailed
            }
            _ => workflow_error_debug(error),
        }
    }

    fn copy_lnurl(value: &str) -> Option<LnurlString> {
        let mut out = LnurlString::new();
        out.push_str(value).ok()?;
        Some(out)
    }

    fn card_keys_to_keyset(keys: &CardKeys) -> bolty_ntag::KeySet {
        [
            *keys.k0.as_bytes(),
            *keys.k1.as_bytes(),
            *keys.k2.as_bytes(),
            *keys.k3.as_bytes(),
            *keys.k4.as_bytes(),
        ]
    }

    fn copy_uid7(uid: &[u8]) -> Option<[u8; 7]> {
        if uid.len() != 7 {
            return None;
        }
        let mut out = [0u8; 7];
        out.copy_from_slice(uid);
        Some(out)
    }

    fn uid_storage_from_fixed(uid: &[u8; 7]) -> Option<[u8; 12]> {
        let mut out = [0u8; 12];
        out[..7].copy_from_slice(uid);
        Some(out)
    }

    fn looks_factory_default(file_settings: Option<&FileSettingsView>) -> bool {
        let Some(file_settings) = file_settings else {
            return false;
        };

        file_settings.file_size == 256
            && matches!(file_settings.comm_mode, CommMode::Plain)
            && file_settings.sdm.is_none()
            && matches!(file_settings.access_rights.read, Access::Free)
            && matches!(file_settings.access_rights.write, Access::Free)
            && matches!(file_settings.access_rights.read_write, Access::Free)
            && matches!(
                file_settings.access_rights.change,
                Access::Key(KeyNumber::Key0)
            )
    }

    fn ndef_ascii(bytes: &[u8]) -> String<MAX_LINE_LEN> {
        let mut out = String::<MAX_LINE_LEN>::new();
        for &byte in bytes {
            let ch = if (0x20..=0x7E).contains(&byte) {
                byte as char
            } else {
                '.'
            };
            if out.push(ch).is_err() {
                break;
            }
        }
        out
    }

    fn push_uid_hex<const N: usize>(out: &mut String<N>, uid: &[u8]) -> core::fmt::Result {
        for byte in uid {
            write!(out, "{byte:02X}")?;
        }
        Ok(())
    }

    fn card_state_label(state: CardState) -> &'static str {
        match state {
            CardState::Blank => "blank",
            CardState::Provisioned(_) => "provisioned",
            CardState::Foreign => "foreign",
            CardState::Unknown => "unknown",
        }
    }

    fn diagnose_state_label(state: DiagnoseState) -> &'static str {
        match state {
            DiagnoseState::Blank => "BLANK",
            DiagnoseState::Provisioned => "PROVISIONED",
            DiagnoseState::AuthDelay => "AUTH_DELAY",
            DiagnoseState::Inconsistent => "INCONSISTENT",
        }
    }

    enum CounterDisplay {
        Value(u32),
        None,
    }

    impl core::fmt::Display for CounterDisplay {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                CounterDisplay::Value(value) => write!(f, "{value}"),
                CounterDisplay::None => f.write_str("none"),
            }
        }
    }

    fn millis() -> u64 {
        let micros = unsafe { esp_idf_sys::esp_timer_get_time() };
        if micros <= 0 { 0 } else { micros as u64 / 1000 }
    }

    fn scan_i2c_bus<I2C>(i2c: &mut I2C) -> Vec<u8>
    where
        I2C: embedded_hal::i2c::I2c,
    {
        let mut found = Vec::new();
        for address in 0x03..=0x77 {
            if i2c.write(address, &[0x00]).is_ok() {
                found.push(address);
            }
        }
        found
    }

    #[cfg(feature = "led-matrix")]
    fn neopixel_off(pin: esp_idf_hal::gpio::Gpio27) {
        use core::time::Duration;
        use esp_idf_hal::rmt::config::{TransmitConfig, TxChannelConfig};
        use esp_idf_hal::rmt::encoder::{BytesEncoder, BytesEncoderConfig};
        use esp_idf_hal::rmt::{PinState, Pulse, Symbol, TxChannelDriver};
        use esp_idf_hal::units::FromValueType as _;

        let config = TxChannelConfig {
            resolution: 10.MHz().into(),
            ..Default::default()
        };

        let mut tx = match TxChannelDriver::new(pin, &config) {
            Ok(tx) => tx,
            Err(e) => {
                log::warn!("NeoPixel RMT init failed: {e:?}");
                return;
            }
        };

        let Ok(t0h) =
            Pulse::new_with_duration(10.MHz().into(), PinState::High, Duration::from_nanos(350))
        else {
            log::warn!("NeoPixel pulse config failed: t0h");
            return;
        };
        let Ok(t0l) =
            Pulse::new_with_duration(10.MHz().into(), PinState::Low, Duration::from_nanos(800))
        else {
            log::warn!("NeoPixel pulse config failed: t0l");
            return;
        };
        let Ok(t1h) =
            Pulse::new_with_duration(10.MHz().into(), PinState::High, Duration::from_nanos(700))
        else {
            log::warn!("NeoPixel pulse config failed: t1h");
            return;
        };
        let Ok(t1l) =
            Pulse::new_with_duration(10.MHz().into(), PinState::Low, Duration::from_nanos(600))
        else {
            log::warn!("NeoPixel pulse config failed: t1l");
            return;
        };

        let encoder_config = BytesEncoderConfig {
            bit0: Symbol::new(t0h, t0l),
            bit1: Symbol::new(t1h, t1l),
            msb_first: true,
            ..Default::default()
        };

        let encoder = match BytesEncoder::with_config(&encoder_config) {
            Ok(encoder) => encoder,
            Err(e) => {
                log::warn!("NeoPixel encoder init failed: {e:?}");
                return;
            }
        };

        let black: [u8; 75] = [0u8; 75];
        if let Err(e) = tx.send_and_wait(encoder, &black, &TransmitConfig::default()) {
            log::warn!("NeoPixel write failed: {e:?}");
        }
    }
}

#[cfg(target_arch = "xtensa")]
fn main() {
    firmware::main();
}

#[cfg(not(target_arch = "xtensa"))]
fn main() {
    println!("bolty-esp32 firmware main is only available on xtensa targets");
}
