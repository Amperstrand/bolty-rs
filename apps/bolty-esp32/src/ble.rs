use std::sync::{Arc, Mutex};

use esp_idf_svc::bt::ble::gap::{AdvConfiguration, BleGapEvent, EspBleGap};
use esp_idf_svc::bt::ble::gatt::server::{ConnectionId, EspGatts, GattsEvent, TransferId};
use esp_idf_svc::bt::ble::gatt::{
    AutoResponse, GattCharacteristic, GattId, GattInterface, GattResponse, GattServiceId,
    GattStatus, Handle, Permission, Property,
};
use esp_idf_svc::bt::{BdAddr, Ble, BtDriver, BtStatus, BtUuid};
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::sys::EspError;
use log::{info, warn};

use heapless::Deque;

const APP_ID: u16 = 0;
const MAX_CONNECTIONS: usize = 2;
const CMD_QUEUE_SIZE: usize = 8;

const SERVICE_UUID: u128 = 0x_b0lt_0000_0000_1000_8000_00805f9b34fb;
const CMD_CHAR_UUID: u128 = 0x_b0lt_0001_0000_1000_8000_00805f9b34fb;
const RSP_CHAR_UUID: u128 = 0x_b0lt_0002_0000_1000_8000_00805f9b34fb;

type ExBtDriver = BtDriver<'static, Ble>;
type ExEspBleGap = Arc<EspBleGap<'static, Ble, Arc<ExBtDriver>>>;
type ExEspGatts = Arc<EspGatts<'static, Ble, Arc<ExBtDriver>>>;

#[derive(Debug, Clone)]
struct Connection {
    peer: BdAddr,
    conn_id: Handle,
    subscribed: bool,
}

#[derive(Default)]
struct State {
    gatt_if: Option<GattInterface>,
    service_handle: Option<Handle>,
    cmd_handle: Option<Handle>,
    rsp_handle: Option<Handle>,
    rsp_cccd_handle: Option<Handle>,
    connections: heapless::Vec<Connection, MAX_CONNECTIONS>,
    response: GattResponse,
    cmd_queue: Deque<heapless::String<256>, CMD_QUEUE_SIZE>,
}

#[derive(Clone)]
pub struct BleTransport {
    gap: ExEspBleGap,
    gatts: ExEspGatts,
    state: Arc<Mutex<State>>,
}

impl BleTransport {
    pub fn start(modem: esp_idf_hal::modem::Modem<'static>) -> Result<Self, EspError> {
        let nvs = esp_idf_svc::nvs::EspDefaultNvsPartition::take()?;
        let bt = Arc::new(BtDriver::new(modem, Some(nvs))?);

        let gap = Arc::new(EspBleGap::new(bt.clone())?);
        let gatts = Arc::new(EspGatts::new(bt.clone())?);

        let transport = Self {
            gap: gap.clone(),
            gatts: gatts.clone(),
            state: Arc::new(Mutex::new(State::default())),
        };

        let t1 = transport.clone();
        transport.gap.subscribe(move |event| {
            let _ = t1.on_gap_event(event);
        })?;

        let t2 = transport.clone();
        transport.gatts.subscribe(move |(gatt_if, event)| {
            let _ = t2.on_gatts_event(gatt_if, event);
        })?;

        transport.gatts.register_app(APP_ID)?;
        info!("BLE: GATTS app registered, advertising will start automatically");

        Ok(transport)
    }

    pub fn poll_command(&self) -> Option<heapless::String<256>> {
        self.state.lock().unwrap().cmd_queue.pop_front()
    }

    pub fn send_response(&self, msg: &str) {
        let gatt_if = self.state.lock().unwrap().gatt_if;
        let rsp_handle = self.state.lock().unwrap().rsp_handle;
        let Some(gi) = gatt_if else { return };
        let Some(rh) = rsp_handle else { return };

        let conns: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .connections
            .iter()
            .filter(|c| c.subscribed)
            .map(|c| c.conn_id)
            .collect();

        for conn_id in conns {
            if let Err(e) = self.gatts.notify(gi, conn_id, rh, msg.as_bytes()) {
                warn!("BLE: notify failed: {e:?}");
            }
        }
    }

    fn on_gap_event(&self, event: BleGapEvent) -> Result<(), EspError> {
        if let BleGapEvent::AdvertisingConfigured(status) = &event {
            if matches!(status, BtStatus::Success) {
                self.gap.start_advertising()?;
                info!("BLE: advertising started as 'Bolty'");
            }
        }
        Ok(())
    }

    fn on_gatts_event(&self, gatt_if: GattInterface, event: GattsEvent) -> Result<(), EspError> {
        match event {
            GattsEvent::ServiceRegistered { status, app_id } => {
                if matches!(status, GattStatus::Ok) && app_id == APP_ID {
                    self.state.lock().unwrap().gatt_if = Some(gatt_if);
                    self.gap.set_device_name("Bolty")?;
                    self.gap.set_adv_conf(&AdvConfiguration {
                        include_name: true,
                        include_txpower: true,
                        flag: 2,
                        service_uuid: Some(BtUuid::uuid128(SERVICE_UUID)),
                        ..Default::default()
                    })?;
                    self.gatts.create_service(
                        gatt_if,
                        &GattServiceId {
                            id: GattId {
                                uuid: BtUuid::uuid128(SERVICE_UUID),
                                inst_id: 0,
                            },
                            is_primary: true,
                        },
                        8,
                    )?;
                }
            }
            GattsEvent::ServiceCreated {
                status,
                service_handle,
                ..
            } => {
                if matches!(status, GattStatus::Ok) {
                    self.state.lock().unwrap().service_handle = Some(service_handle);
                    self.gatts.start_service(service_handle)?;
                    self.gatts.add_characteristic(
                        service_handle,
                        &GattCharacteristic {
                            uuid: BtUuid::uuid128(CMD_CHAR_UUID),
                            permissions: enum_set!(Permission::Write | Permission::WriteEncryptedMitm),
                            properties: enum_set!(Property::Write),
                            max_len: 200,
                            auto_rsp: AutoResponse::ByApp,
                        },
                        &[],
                    )?;
                    self.gatts.add_characteristic(
                        service_handle,
                        &GattCharacteristic {
                            uuid: BtUuid::uuid128(RSP_CHAR_UUID),
                            permissions: enum_set!(Permission::Read | Permission::Write),
                            properties: enum_set!(Property::Notify),
                            max_len: 200,
                            auto_rsp: AutoResponse::ByApp,
                        },
                        &[],
                    )?;
                }
            }
            GattsEvent::CharacteristicAdded {
                status,
                attr_handle,
                service_handle,
                char_uuid,
            } => {
                if !matches!(status, GattStatus::Ok) {
                    return Ok(());
                }
                let mut state = self.state.lock().unwrap();
                if state.service_handle != Some(service_handle) {
                    return Ok(());
                }
                if char_uuid == BtUuid::uuid128(CMD_CHAR_UUID) {
                    state.cmd_handle = Some(attr_handle);
                } else if char_uuid == BtUuid::uuid128(RSP_CHAR_UUID) {
                    state.rsp_handle = Some(attr_handle);
                    drop(state);
                    self.gatts.add_descriptor(
                        service_handle,
                        &esp_idf_svc::bt::ble::gatt::GattDescriptor {
                            uuid: BtUuid::uuid16(0x2902),
                            permissions: enum_set!(Permission::Read | Permission::Write),
                        },
                    )?;
                }
            }
            GattsEvent::DescriptorAdded {
                status,
                attr_handle,
                descr_uuid,
                ..
            } => {
                if matches!(status, GattStatus::Ok) && descr_uuid == BtUuid::uuid16(0x2902) {
                    self.state.lock().unwrap().rsp_cccd_handle = Some(attr_handle);
                    info!("BLE: GATT server ready (cmd + notify characteristics)");
                }
            }
            GattsEvent::PeerConnected { conn_id, addr, .. } => {
                let mut state = self.state.lock().unwrap();
                let _ = state.connections.push(Connection {
                    peer: addr,
                    conn_id,
                    subscribed: false,
                });
                info!("BLE: client connected {addr}");
            }
            GattsEvent::PeerDisconnected { addr, .. } => {
                let mut state = self.state.lock().unwrap();
                if let Some(idx) = state.connections.iter().position(|c| c.peer == addr) {
                    state.connections.swap_remove(idx);
                }
                info!("BLE: client disconnected {addr}");
            }
            GattsEvent::Write {
                conn_id,
                trans_id,
                addr,
                handle,
                offset,
                need_rsp,
                value,
                ..
            } => {
                let mut state = self.state.lock().unwrap();
                let cmd_h = state.cmd_handle;
                let cccd_h = state.rsp_cccd_handle;

                if Some(handle) == cccd_h {
                    if offset == 0 && value.len() == 2 {
                        let v = u16::from_le_bytes([value[0], value[1]]);
                        if let Some(conn) =
                            state.connections.iter_mut().find(|c| c.conn_id == conn_id)
                        {
                            conn.subscribed = v != 0;
                            info!("BLE: client {addr} subscribed={}", v != 0);
                        }
                    }
                } else if Some(handle) == cmd_h {
                    let text = core::str::from_utf8(value).unwrap_or("");
                    let mut cmd = heapless::String::<256>::new();
                    let _ = cmd.push_str(text.trim());
                    let _ = state.cmd_queue.push_back(cmd);
                    info!("BLE: command received from {addr}: {text}");
                }

                drop(state);

                if need_rsp {
                    let _ =
                        self.gatts
                            .send_response(gatt_if, conn_id, trans_id, GattStatus::Ok, None);
                }
            }
            GattsEvent::Mtu { mtu, .. } => {
                info!("BLE: MTU negotiated: {mtu}");
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn wait_for_ready(transport: &BleTransport, timeout_ms: u64) -> bool {
    let start = unsafe { esp_idf_svc::sys::xTaskGetTickCount() };
    let timeout_ticks = (timeout_ms / 10) as u32;
    loop {
        {
            let state = transport.state.lock().unwrap();
            if state.cmd_handle.is_some() && state.rsp_cccd_handle.is_some() {
                return true;
            }
        }
        let now = unsafe { esp_idf_svc::sys::xTaskGetTickCount() };
        if now - start > timeout_ticks {
            return false;
        }
        FreeRtos::delay_ms(100);
    }
}
