use std::sync::{Arc, Mutex};

use esp32_nimble::{
    BLEAdvertisementData, BLEDevice, NimbleProperties, enums::*, utilities::BleUuid, uuid128,
};
use heapless::Deque;
use log::info;

const CMD_QUEUE_SIZE: usize = 8;

pub const SERVICE_UUID: BleUuid = uuid128!("b0170000-0000-1000-8000-00805f9b34fb");
pub const CMD_CHAR_UUID: BleUuid = uuid128!("b0170001-0000-1000-8000-00805f9b34fb");
pub const RSP_CHAR_UUID: BleUuid = uuid128!("b0170002-0000-1000-8000-00805f9b34fb");

#[derive(Default)]
struct State {
    cmd_queue: Deque<heapless::String<256>, CMD_QUEUE_SIZE>,
    rsp_char: Option<Arc<Mutex<esp32_nimble::BLECharacteristic>>>,
    connected: bool,
}

#[derive(Clone)]
pub struct BleTransport {
    state: Arc<Mutex<State>>,
}

impl BleTransport {
    pub fn start() -> Result<Self, &'static str> {
        let device = BLEDevice::take();
        let advertising = device.get_advertising();

        device
            .security()
            .set_auth(AuthReq::all())
            .set_io_cap(SecurityIOCap::DisplayOnly)
            .resolve_rpa();

        let state = Arc::new(Mutex::new(State::default()));
        let server = device.get_server();

        let state_connect = state.clone();
        server.on_connect(move |_server, desc| {
            info!("BLE: client connected {:?}", desc);
            state_connect.lock().unwrap().connected = true;
        });

        let state_disconnect = state.clone();
        server.on_disconnect(move |desc, reason| {
            info!("BLE: client disconnected {:?} ({:?})", desc, reason);
            state_disconnect.lock().unwrap().connected = false;
        });

        server.on_authentication_complete(move |_server, _desc, result| {
            info!("BLE: auth result: {:?}", result);
        });

        let service = server.create_service(SERVICE_UUID);

        let cmd_state = state.clone();
        let cmd_char = service.lock().create_characteristic(
            CMD_CHAR_UUID,
            NimbleProperties::WRITE | NimbleProperties::WRITE_ENC | NimbleProperties::WRITE_AUTHEN,
        );
        cmd_char.lock().on_write(move |args| {
            let data = args.recv_data();
            if let Ok(text) = core::str::from_utf8(data) {
                let mut cmd = heapless::String::<256>::new();
                let _ = cmd.push_str(text.trim());
                info!("BLE: cmd: {text}");
                cmd_state.lock().unwrap().cmd_queue.push_back(cmd).ok();
            }
        });

        let rsp_char = service.lock().create_characteristic(
            RSP_CHAR_UUID,
            NimbleProperties::READ | NimbleProperties::READ_ENC | NimbleProperties::NOTIFY,
        );
        rsp_char.lock().set_value(b"");
        state.lock().unwrap().rsp_char = Some(Arc::new(Mutex::new(rsp_char)));

        advertising
            .lock()
            .set_data(
                BLEAdvertisementData::new()
                    .name("Bolty")
                    .add_service_uuid(SERVICE_UUID),
            )
            .map_err(|_| "adv set_data failed")?;
        advertising.lock().start().map_err(|_| "adv start failed")?;

        info!("BLE: NimBLE server 'Bolty' (encrypted, requires pairing)");

        Ok(Self { state })
    }

    pub fn poll_command(&self) -> Option<heapless::String<256>> {
        self.state.lock().unwrap().cmd_queue.pop_front()
    }

    pub fn send_response(&self, msg: &str) {
        let state = self.state.lock().unwrap();
        if let Some(ref rsp) = state.rsp_char {
            let mut c = rsp.lock().unwrap();
            c.set_value(msg.as_bytes());
            c.notify();
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state.lock().unwrap().connected
    }
}
