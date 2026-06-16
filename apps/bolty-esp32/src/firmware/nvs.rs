use esp_idf_sys::{
    ESP_OK, nvs_close, nvs_commit, nvs_flash_init, nvs_get_str, nvs_get_u8, nvs_get_u32,
    nvs_handle_t, nvs_open, nvs_open_mode_t_NVS_READONLY, nvs_open_mode_t_NVS_READWRITE,
    nvs_set_str, nvs_set_u8, nvs_set_u32,
};
use heapless::String;

const MAX_LNURL_LEN: usize = 256;

static NVS_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(super) fn init() {
    if NVS_READY.load(core::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let rc = unsafe { nvs_flash_init() };
    NVS_READY.store(rc == ESP_OK, core::sync::atomic::Ordering::SeqCst);
}

pub(super) fn load_lnurl() -> Option<String<MAX_LNURL_LEN>> {
    init();
    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(c"bolty".as_ptr(), nvs_open_mode_t_NVS_READONLY, &mut handle);
        if rc != ESP_OK {
            return None;
        }

        let mut required: usize = 0;
        let rc = nvs_get_str(
            handle,
            c"lnurl".as_ptr(),
            core::ptr::null_mut(),
            &mut required,
        );
        if rc != ESP_OK || required == 0 || required > MAX_LNURL_LEN + 1 {
            nvs_close(handle);
            return None;
        }

        let mut buf = [0u8; MAX_LNURL_LEN + 1];
        let rc = nvs_get_str(
            handle,
            c"lnurl".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut required,
        );
        nvs_close(handle);

        if rc != ESP_OK {
            return None;
        }

        let s = core::str::from_utf8(&buf[..required - 1]).ok()?;
        let mut out = String::<MAX_LNURL_LEN>::new();
        out.push_str(s).ok()?;
        Some(out)
    }
}

pub(super) fn save_lnurl(url: &str) -> bool {
    init();
    let url_bytes = url.as_bytes();
    if url_bytes.len() >= MAX_LNURL_LEN {
        return false;
    }

    let mut buf = [0u8; MAX_LNURL_LEN + 1];
    buf[..url_bytes.len()].copy_from_slice(url_bytes);

    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(
            c"bolty".as_ptr(),
            nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        );
        if rc != ESP_OK {
            return false;
        }

        let rc = nvs_set_str(handle, c"lnurl".as_ptr(), buf.as_ptr());
        if rc != ESP_OK {
            nvs_close(handle);
            return false;
        }

        let rc = nvs_commit(handle);
        nvs_close(handle);
        rc == ESP_OK
    }
}

const MAX_BTN_MODE_LEN: usize = 16;

pub(super) fn load_button_mode() -> Option<String<MAX_BTN_MODE_LEN>> {
    init();
    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(c"bolty".as_ptr(), nvs_open_mode_t_NVS_READONLY, &mut handle);
        if rc != ESP_OK {
            return None;
        }

        let mut required: usize = 0;
        let rc = nvs_get_str(
            handle,
            c"btn_mode".as_ptr(),
            core::ptr::null_mut(),
            &mut required,
        );
        if rc != ESP_OK || required == 0 || required > MAX_BTN_MODE_LEN + 1 {
            nvs_close(handle);
            return None;
        }

        let mut buf = [0u8; MAX_BTN_MODE_LEN + 1];
        let rc = nvs_get_str(
            handle,
            c"btn_mode".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut required,
        );
        nvs_close(handle);

        if rc != ESP_OK {
            return None;
        }

        let s = core::str::from_utf8(&buf[..required - 1]).ok()?;
        let mut out = String::<MAX_BTN_MODE_LEN>::new();
        out.push_str(s).ok()?;
        Some(out)
    }
}

pub(super) fn save_button_mode(mode: &str) -> bool {
    init();
    let mode_bytes = mode.as_bytes();
    if mode_bytes.len() >= MAX_BTN_MODE_LEN {
        return false;
    }

    let mut buf = [0u8; MAX_BTN_MODE_LEN + 1];
    buf[..mode_bytes.len()].copy_from_slice(mode_bytes);

    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(
            c"bolty".as_ptr(),
            nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        );
        if rc != ESP_OK {
            return false;
        }

        let rc = nvs_set_str(handle, c"btn_mode".as_ptr(), buf.as_ptr());
        if rc != ESP_OK {
            nvs_close(handle);
            return false;
        }

        let rc = nvs_commit(handle);
        nvs_close(handle);
        rc == ESP_OK
    }
}

pub(super) fn load_boot_count() -> u32 {
    init();
    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(c"bolty".as_ptr(), nvs_open_mode_t_NVS_READONLY, &mut handle);
        if rc != ESP_OK {
            return 0;
        }

        let mut value: u32 = 0;
        let rc = nvs_get_u32(handle, c"bootcnt".as_ptr(), &mut value);
        nvs_close(handle);

        if rc == ESP_OK { value } else { 0 }
    }
}

pub(super) fn save_boot_count(count: u32) {
    init();
    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(
            c"bolty".as_ptr(),
            nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        );
        if rc != ESP_OK {
            return;
        }

        let rc = nvs_set_u32(handle, c"bootcnt".as_ptr(), count);
        if rc == ESP_OK {
            nvs_commit(handle);
        }
        nvs_close(handle);
    }
}

pub(super) fn save_crash_info(reason: u8, boot_count: u32) {
    init();
    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(
            c"bolty".as_ptr(),
            nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        );
        if rc != ESP_OK {
            return;
        }

        let rc_reason = nvs_set_u8(handle, c"crashrsn".as_ptr(), reason);
        let rc_boot = nvs_set_u32(handle, c"crashboot".as_ptr(), boot_count);
        if rc_reason == ESP_OK && rc_boot == ESP_OK {
            nvs_commit(handle);
        }
        nvs_close(handle);
    }
}

pub(super) fn load_crash_info() -> Option<(u8, u32)> {
    init();
    unsafe {
        let mut handle: nvs_handle_t = 0;
        let rc = nvs_open(c"bolty".as_ptr(), nvs_open_mode_t_NVS_READONLY, &mut handle);
        if rc != ESP_OK {
            return None;
        }

        let mut reason: u8 = 0;
        let mut boot_count: u32 = 0;
        let rc_reason = nvs_get_u8(handle, c"crashrsn".as_ptr(), &mut reason);
        let rc_boot = nvs_get_u32(handle, c"crashboot".as_ptr(), &mut boot_count);
        nvs_close(handle);

        if rc_reason == ESP_OK && rc_boot == ESP_OK {
            Some((reason, boot_count))
        } else {
            None
        }
    }
}
