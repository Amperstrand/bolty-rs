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

#[cfg(all(target_arch = "xtensa", feature = "board-m5atom", feature = "board-m5stick"))]
compile_error!("Enable exactly one board feature: `board-m5atom` or `board-m5stick`.");

#[cfg(all(
    target_arch = "xtensa",
    not(any(feature = "board-m5atom", feature = "board-m5stick"))
))]
compile_error!("Enable one board feature: `board-m5atom` or `board-m5stick`.");

#[cfg(all(target_arch = "xtensa", not(feature = "nfc-mfrc522")))]
compile_error!("The current firmware requires the `nfc-mfrc522` feature.");

#[cfg(all(target_arch = "xtensa", feature = "led-matrix", not(feature = "board-m5atom")))]
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
    use std::sync::{Arc, Mutex};

    use bolty_core::{
        assessment::{CardAssessment, CardState},
        commands::{Command, CommandError, parse_command},
        config::{BoltyConfig, IssuerConfig, LnurlString, MessageString},
        issuer::assess_card,
        secret::CardKeys,
        service::{BoltyService, ServiceStatus, WorkflowResult},
        workflow::dispatch_command,
    };
    use bolty_mfrc522::{DEFAULT_I2C_ADDRESS, Mfrc522Transceiver, Mfrc522Transport};
    use esp_idf_hal::{
        delay::FreeRtos,
        i2c::{I2cConfig, I2cDriver},
        peripherals::Peripherals,
        units::FromValueType,
    };
    #[cfg(feature = "ota")]
    use esp_idf_hal::reset::restart;
    use esp_idf_sys as _;
    use heapless::String;
    use log::info;

    use crate::block_on;
    #[cfg(feature = "display-st7789")]
    use crate::display;
    #[cfg(feature = "rest")]
    use crate::rest::{RestBoltyService, RestServer};
    #[cfg(feature = "ota")]
    use crate::ota::OtaUpdater;
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

        #[cfg(feature = "board-m5atom")]
        let (i2c_sda, i2c_scl) = (peripherals.pins.gpio26, peripherals.pins.gpio32);
        #[cfg(feature = "board-m5stick")]
        let (i2c_sda, i2c_scl) = (peripherals.pins.gpio32, peripherals.pins.gpio33);

        FreeRtos::delay_ms(50);

        let i2c = match I2cDriver::new(
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

        let xcvr = match Mfrc522Transceiver::from_i2c(i2c, DEFAULT_I2C_ADDRESS) {
            Ok(xcvr) => xcvr,
            Err(e) => {
                log::error!("MFRC522 init failed: {e:?}");
                loop {
                    FreeRtos::delay_ms(1000);
                }
            }
        };
        log::info!("MFRC522 initialized at 0x{:02X}", DEFAULT_I2C_ADDRESS);

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

        let mut serial = SerialConsole::new();
        let initial_config = BoltyConfig::default();
        let config = Arc::new(Mutex::new(initial_config.clone()));
        let service = Arc::new(Mutex::new(Esp32BoltyService::new(xcvr, initial_config)));

        #[cfg(feature = "display-st7789")]
        display::set_nfc_ready(true);
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
        transceiver: Mfrc522Transceiver<I2C>,
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
        fn new(transceiver: Mfrc522Transceiver<I2C>, current_config: BoltyConfig) -> Self {
            let mut service = Self {
                transceiver,
                current_config,
                keys: None,
                authenticated_key0: None,
                last_card: CardAssessment::default(),
                status: ServiceStatus {
                    last_uid: None,
                    nfc_ready: true,
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
            if self.keys.is_none() {
                self.keys = self.current_config.pending_keys.clone();
            }
        }

        fn activate_transport(&mut self) -> Result<Mfrc522Transport<'_, I2C>, WorkflowResult> {
            Mfrc522Transport::activate(&mut self.transceiver).map_err(|_| {
                self.status.nfc_ready = true;
                self.last_card = CardAssessment::default();
                WorkflowResult::CardNotPresent
            })
        }

        fn inspect_with_key(
            &mut self,
            key: &[u8; 16],
        ) -> Result<CardAssessment, WorkflowResult> {
            let mut transport = self.activate_transport()?;
            let uid = copy_uid7(transport.uid())
                .ok_or_else(|| workflow_error("unsupported uid length"))?;
            let key_versions = block_on(bolty_ntag::check_key_versions(&mut transport, key, RND_A))
                .map_err(|err| map_ntag_error(&err))?;

            let issuer = self.current_config.pending_issuer.as_ref().map(|issuer_key| IssuerConfig {
                name: self.current_config.issuer_name.clone(),
                issuer_key: issuer_key.clone(),
                ..IssuerConfig::default()
            });
            let issuers = issuer
                .as_ref()
                .map(core::slice::from_ref)
                .unwrap_or(&[]);

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

            let mut transport = match self.activate_transport() {
                Ok(transport) => transport,
                Err(err) => return err,
            };

            match block_on(bolty_ntag::wipe(&mut transport, &card_keys_to_keyset(keys), RND_A)) {
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
            if read == 1 {
                Some(byte)
            } else {
                None
            }
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
                serial.fail(command_error_message(err));
                return;
            }
        };

        #[cfg(feature = "wifi")]
        match &command {
            Command::SetWifi { ssid, password } => {
                let Some(manager) = wifi_manager.as_mut() else {
                    serial.fail("wifi unavailable");
                    return;
                };
                match manager.connect(ssid, password) {
                    Ok(()) => {
                        serial.ok("wifi connected");
                        #[cfg(feature = "display-st7789")]
                        if let Some(ip) = wifi_ip_string() {
                            display::set_wifi(ip.as_str());
                        }
                        #[cfg(feature = "rest")]
                        {
                            if rest_server.is_none() {
                                match RestServer::start(REST_PORT, Arc::clone(config), Arc::clone(service)) {
                                    Ok(server) => {
                                        *rest_server = Some(server);
                                        serial.ok("rest server started");
                                    }
                                    Err(err) => {
                                        serial.fail(rest_error_message(&err).as_str());
                                        return;
                                    }
                                }
                            }

                            match manager.advertise_http_service(REST_PORT) {
                                Ok(()) => serial.ok("mdns bolty.local active"),
                                Err(err) => serial.fail(wifi_error_message(&err).as_str()),
                            }
                        }
                    }
                    Err(err) => serial.fail(wifi_error_message(&err).as_str()),
                }
                return;
            }
            Command::WifiOff => {
                let Some(manager) = wifi_manager.as_mut() else {
                    serial.fail("wifi unavailable");
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
                    }
                    Err(err) => serial.fail(wifi_error_message(&err).as_str()),
                }
                return;
            }
            #[cfg(feature = "ota")]
            Command::Ota { url } => {
                match OtaUpdater::update(url.as_str()) {
                    Ok(()) => {
                        serial.ok("rebooting");
                        restart();
                    }
                    Err(err) => {
                        let mut message = String::<128>::new();
                        let _ = write!(message, "{err}");
                        serial.fail(message.as_str());
                    }
                }
                return;
            }
            _ => {}
        }

        #[cfg(all(feature = "wifi", not(feature = "ota")))]
        if matches!(&command, Command::Ota { .. }) {
            serial.fail("ota feature disabled");
            return;
        }

        #[cfg(not(feature = "wifi"))]
        if matches!(&command, Command::SetWifi { .. } | Command::WifiOff | Command::Ota { .. }) {
            let _ = wifi_manager;
            serial.fail("wifi feature disabled");
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
        let result = dispatch_command(command, &mut *service, &mut config);
        service.sync_from(&config);

        match command_copy {
            Command::Help => {
                print_help(serial);
                serial.ok("help");
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
        serial.line("Commands: help status uid keys <k0..k4> issuer [hex] url <lnurl> burn wipe inspect check");
        #[cfg(feature = "wifi")]
        serial.line("WiFi: wifi <ssid> <password> | wifi off");
        #[cfg(feature = "ota")]
        serial.line("OTA: ota <url>");
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
            status.lnurl.as_ref().map(LnurlString::as_str).unwrap_or("none")
        );
        serial.ok(line.as_str());
    }

    fn print_uid<I2C>(serial: &mut SerialConsole, service: &Esp32BoltyService<I2C>)
    where
        I2C: embedded_hal::i2c::I2c,
    {
        if let Some(last_uid) = service.get_status().last_uid {
            let mut uid = String::<32>::new();
            let _ = push_uid_hex(&mut uid, &last_uid);
            serial.ok(uid.as_str());
        } else {
            serial.fail("no uid");
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
            }
            other => print_workflow_result(serial, other),
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
            }
            (Command::SetKeys(_), WorkflowResult::Success) => serial.ok("keys staged"),
            (Command::SetIssuer(_), WorkflowResult::Success) => serial.ok("issuer staged"),
            (Command::SetUrl(_), WorkflowResult::Success) => serial.ok("lnurl staged"),
            (Command::Burn, WorkflowResult::Success) => serial.ok("burn complete"),
            (Command::Wipe, WorkflowResult::Success) => serial.ok("wipe complete"),
            (_, other) => print_workflow_result(serial, other),
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
            WorkflowResult::AuthFailed | WorkflowResult::AuthDelay | WorkflowResult::WipeRefused => {
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

    fn workflow_error(message: &str) -> WorkflowResult {
        let mut out = MessageString::new();
        if out.push_str(message).is_err() {
            let _ = out.push_str("workflow error");
        }
        WorkflowResult::Error(out)
    }

    fn workflow_error_debug<T: core::fmt::Debug>(error: &T) -> WorkflowResult {
        let mut out = MessageString::new();
        if write!(out, "{error:?}").is_err() {
            let _ = out.push_str("debug formatting overflow");
        }
        WorkflowResult::Error(out)
    }

    fn map_ntag_error<T>(error: &bolty_ntag::Error<T>) -> WorkflowResult
    where
        T: core::error::Error + core::fmt::Debug,
    {
        match error {
            err if bolty_ntag::is_authentication_delay(err) => WorkflowResult::AuthDelay,
            bolty_ntag::Error::Session(ntag424::SessionError::ErrorResponse(_)) => {
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

    fn millis() -> u64 {
        let micros = unsafe { esp_idf_sys::esp_timer_get_time() };
        if micros <= 0 {
            0
        } else {
            micros as u64 / 1000
        }
    }

    #[cfg(feature = "led-matrix")]
    fn neopixel_off(pin: esp_idf_hal::gpio::Gpio27) {
        use core::time::Duration;
        use esp_idf_hal::rmt::config::{TxChannelConfig, TransmitConfig};
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
