use core::fmt;

use bolty_core::config::{WifiPasswordString, WifiSsidString};
use esp_idf_hal::modem::Modem;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    nvs::EspDefaultNvsPartition,
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi},
};
use esp_idf_sys::EspError;
use log::info;

#[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
use esp_idf_svc::mdns::EspMdns;

const MDNS_HOSTNAME: &str = "bolty";

#[derive(Debug)]
pub enum WifiError {
    SsidTooLong,
    PasswordTooLong,
    Esp(EspError),
}

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SsidTooLong => f.write_str("ssid too long"),
            Self::PasswordTooLong => f.write_str("password too long"),
            Self::Esp(err) => write!(f, "{err}"),
        }
    }
}

impl From<EspError> for WifiError {
    fn from(value: EspError) -> Self {
        Self::Esp(value)
    }
}

pub struct WifiManager {
    wifi: BlockingWifi<EspWifi<'static>>,
    ssid: Option<WifiSsidString>,
    password: Option<WifiPasswordString>,
    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    mdns: Option<EspMdns>,
}

impl WifiManager {
    pub fn new(modem: Modem) -> Result<Self, WifiError> {
        let sys_loop = EspSystemEventLoop::take()?;
        let nvs = EspDefaultNvsPartition::take()?;
        let wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;

        Ok(Self {
            wifi,
            ssid: None,
            password: None,
            #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
            mdns: None,
        })
    }

    pub fn connect(
        &mut self,
        ssid: &WifiSsidString,
        password: &WifiPasswordString,
    ) -> Result<(), WifiError> {
        #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
        {
            self.mdns = None;
        }

        if self.wifi.is_connected()? {
            self.wifi.disconnect()?;
        }
        if self.wifi.is_started()? {
            self.wifi.stop()?;
        }

        self.ssid = Some(copy_ssid(ssid.as_str())?);
        self.password = Some(copy_password(password.as_str())?);

        let wifi_configuration = Configuration::Client(ClientConfiguration {
            ssid: self.ssid.clone().ok_or(WifiError::SsidTooLong)?,
            password: self.password.clone().ok_or(WifiError::PasswordTooLong)?,
            auth_method: AuthMethod::WPA2Personal,
            bssid: None,
            channel: None,
            ..Default::default()
        });

        self.wifi.set_configuration(&wifi_configuration)?;
        self.wifi.start()?;
        self.wifi.connect()?;
        self.wifi.wait_netif_up()?;

        #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
        self.start_mdns()?;

        let ip_info = self.wifi.wifi().sta_netif().get_ip_info()?;
        info!("WiFi connected: ip={}", ip_info.ip);

        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), WifiError> {
        #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
        {
            self.mdns = None;
        }

        if self.wifi.is_connected()? {
            self.wifi.disconnect()?;
        }
        if self.wifi.is_started()? {
            self.wifi.stop()?;
        }

        self.ssid = None;
        self.password = None;

        info!("WiFi shutdown complete");

        Ok(())
    }

    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    fn start_mdns(&mut self) -> Result<(), WifiError> {
        let mut mdns = EspMdns::take()?;
        mdns.set_hostname(MDNS_HOSTNAME)?;
        mdns.set_instance_name(MDNS_HOSTNAME)?;
        self.mdns = Some(mdns);
        Ok(())
    }
}

fn copy_ssid(value: &str) -> Result<WifiSsidString, WifiError> {
    let mut out = WifiSsidString::new();
    out.push_str(value).map_err(|_| WifiError::SsidTooLong)?;
    Ok(out)
}

fn copy_password(value: &str) -> Result<WifiPasswordString, WifiError> {
    let mut out = WifiPasswordString::new();
    out.push_str(value)
        .map_err(|_| WifiError::PasswordTooLong)?;
    Ok(out)
}
