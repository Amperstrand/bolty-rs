//! TCP OTA flash server (:3232) — the bench recovery door for
//! `board-nucula` (issue #115): without it, every bolty push over the
//! OTA seat is one-way (the bolty build has no other network service,
//! so restoring ccid/wallet firmware would require serial).
//!
//! Wire-protocol port of ccid-firmware-rs `firmware/esp32-ccid/src/ota.rs`
//! (Amperstrand, GPL-2.0-or-later — the "or later" permits this copy into
//! bolty's GPL-3.0-or-later tree). Only the OTA1 form is served: `"OTA1"`
//! magic + u32-LE image size + raw app-image bytes; `esp_ota_end` runs a
//! full `esp_image_verify` (segments, checksum, SHA-256) BEFORE the boot
//! partition switches, so a corrupt or truncated push leaves the running
//! image untouched. The token-authenticated OTA2 form stays ccid-side.
//! Host client: ccid-firmware-rs `tests/hardware/ota/ota_push.py`.
//!
//! Requires the on-device partition table to carry OTA slots (the bench
//! nucula does — ccid's `partitions-ota.csv`); with a factory-only table
//! the server refuses pushes with "no OTA partition" and keeps serving.

use core::time::Duration;

use std::io::{Read, Write};
use std::net::TcpListener;

use esp_idf_sys::{
    esp_ota_abort, esp_ota_begin, esp_ota_end, esp_ota_get_next_update_partition,
    esp_ota_set_boot_partition, esp_ota_write, esp_restart,
};

const PORT: u16 = 3232;
const OTA_SIZE_UNKNOWN: usize = 0xFFFF_FFFF;
const CHUNK: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Read the announced image size off the socket and write it to the OTA
/// partition. Fails (pre-commit) on any stalled read or write reject.
fn stream_image(
    stream: &mut impl Read,
    handle: esp_idf_sys::esp_ota_handle_t,
    size: usize,
) -> Result<(), &'static str> {
    let mut remaining = size;
    let mut buf = [0u8; CHUNK];
    while remaining > 0 {
        let want = remaining.min(CHUNK);
        stream
            .read_exact(&mut buf[..want])
            .map_err(|_| "image read failed")?;
        let rc = unsafe {
            esp_ota_write(
                handle,
                buf[..want].as_ptr() as *const core::ffi::c_void,
                want,
            )
        };
        if rc != 0 {
            return Err("esp_ota_write failed");
        }
        remaining -= want;
    }
    Ok(())
}

/// Spawn the server task once per boot (idempotence guarded by the
/// caller in the frontend).
pub fn spawn() {
    let _ = std::thread::Builder::new()
        .stack_size(16 * 1024)
        .name("ota".into())
        .spawn(server);
}

fn server() {
    let listener = match TcpListener::bind(("0.0.0.0", PORT)) {
        Ok(listener) => listener,
        Err(err) => {
            log::warn!("ota: bind failed: {err}");
            return;
        }
    };
    log::warn!("ota: listening on :{PORT}");
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Deadline every read/write — a stalled client fails out
                // instead of pinning this accept thread forever.
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                if let Err(message) = handle(&mut stream) {
                    log::warn!("ota: update failed: {message}");
                    let _ = stream.write_all(&[b'E']);
                }
            }
            Err(err) => log::warn!("ota: accept: {err}"),
        }
    }
}

fn handle(stream: &mut impl Read) -> Result<(), &'static str> {
    let mut header = [0u8; 8];
    stream
        .read_exact(&mut header)
        .map_err(|_| "header read failed")?;
    let magic: [u8; 4] = header
        .get(..4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or("header too short")?;
    if magic != *b"OTA1" {
        return Err("bad magic (only OTA1 is served)");
    }
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;

    // Size gate against the ACTUAL OTA partition, before anything is
    // erased or written.
    // Safety: read-only use of the partition-table-owned pointer.
    let partition = unsafe { esp_ota_get_next_update_partition(core::ptr::null()) };
    if partition.is_null() {
        return Err("no OTA partition — partition table lacks ota slots");
    }
    // Safety: aligned read of the fixed esp_partition_t layout.
    let partition_size = unsafe { (*partition).size } as usize;
    if size == 0 || size > partition_size {
        return Err("image size rejected");
    }

    let mut handle: esp_idf_sys::esp_ota_handle_t = 0;
    let rc = unsafe { esp_ota_begin(partition, OTA_SIZE_UNKNOWN, &mut handle) };
    if rc != 0 {
        return Err("esp_ota_begin failed");
    }

    // Every failure after esp_ota_begin aborts the handle — a leaked
    // handle leaves the next attempt wedged until reboot.
    if let Err(message) = stream_image(stream, handle, size) {
        // Safety: single-threaded app_update API use on our own handle.
        unsafe { esp_ota_abort(handle) };
        return Err(message);
    }

    // esp_ota_end is the commit gate: it validates image integrity
    // BEFORE the boot switch; on failure it finalizes the handle itself.
    let rc = unsafe { esp_ota_end(handle) };
    if rc != 0 {
        return Err("esp_ota_end failed — image rejected");
    }
    let rc = unsafe { esp_ota_set_boot_partition(partition) };
    if rc != 0 {
        return Err("set_boot_partition failed");
    }
    log::warn!("ota: {size} bytes written, boot partition switched, rebooting");
    std::thread::sleep(Duration::from_millis(500));
    // Safety: process-ending chip restart.
    unsafe { esp_restart() }
}
