#!/usr/bin/env python3
"""bolty-console — persistent serial console daemon for the bolty M5Stick rig.

WHY THIS EXISTS (bolty-rs docs/lessons-learned.md B11): every open()/close()
of the FT232 USB-UART fires DTR/RTS TIOCMSET transitions that corrupt this
bridge's USB state machine — the device disconnects (11 events in the lab
box's kernel log) and only a USB rebind recovers it. The fix is structural:
open the port exactly ONCE, keep it open forever, and expose the console over
a unix socket so tooling never touches the tty again.

Protocol (line-based, one command per connection):
  <anything>   -> forwarded to the serial console; reply = collected output
                  lines until 1.0s of quiescence (or 40s cap), then "OK".
  PING         -> immediate daemon health (no serial write): hb_age etc.
  RAW <sec>    -> passive capture for <sec> seconds (no serial write).

All RX is journaled (with timestamps) to the --log file for post-mortems.

Flight recorder (2026-10-27, owner ask after issue #222): every line —
device output AND host-side events (daemon start, serial stalls, USB
presence transitions) — enters an in-memory ring. When a TRIGGER fires
(reset banner, panic signature, coredump line, or a binary-garbage
line), the ring plus a post-trigger tail is snapshotted to
--incident-dir/<utc-ts>-<seat>.log so the last X minutes around an
interesting event survive even if the device wedges right after. The
2026-10-26 incidents were reconstructed from journals whose time-only
stamps made multi-day correlation guesswork; this makes the lead-up
recordable and dated.
"""
import argparse
import os
import re
import socket
import sys
import threading
import time
from collections import deque

import serial

DEFAULT_PORT = "/dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0"
QUIET_S = 1.0
HARD_CAP_S = 40.0
# How long a SerialException read storm is retried on the SAME fd before
# escalating to exit(3) (systemd reopen). Every reopen pulses DTR/RTS:
# pyserial drops the two lines with sequential TIOCMBIC ioctls (cdc_acm
# rejects atomic TIOCMSET with EINVAL), and on the ESP32-C3's USB-Serial/
# JTAG console the DTR-low/RTS-high intermediate state is a
# USB_UART_CHIP_RESET. Keep this window long enough that a transient CDC
# stall never costs a board reset (C3 incident 2026-10-26/27, issue #222:
# a crash-restart loop reset the nucula every ~6 s for 10+ minutes).
STALL_RETRY_S = 30.0

# ---- flight recorder ------------------------------------------------------
# Ring depth: ~12000 lines ≈ 33 h of 10 s heartbeats, or tens of minutes of
# a 5 Hz warning spray — whichever comes first, the LEAD-UP is what matters.
RING_LINES = 12000
# Lines captured AFTER the trigger before the snapshot is written.
POST_TRIGGER_LINES = 40
# Minimum seconds between snapshots of the SAME trigger kind (burst dedup).
SNAPSHOT_COOLDOWN_S = 60.0
# Device-output signatures that indicate something interesting happened.
TRIGGER_PATTERNS = [
    re.compile(p)
    for p in (
        r"rst:0x",           # any reset banner (cause code in the line)
        r"ESP-ROM:",         # boot ROM banner (reset without cause line)
        r"Guru Meditation",
        r"panic",
        r"abort",
        r"[Bb]acktrace",
        r"[Cc]ore [Dd]ump",  # esp_core_dump_flash discovery/writing
        r"watchdog",
        r"POWERON_RESET",
        r"exception",
    )
]
# A line whose non-printable byte ratio exceeds this is "binary garbage" —
# the 2026-10-26 C3 wedge emitted structured binary before dying (issue
# #222's "console garbage"); ratio-detection catches that class without
# pinning the exact bytes.
GARBAGE_RATIO = 0.25
GARBAGE_MIN_LEN = 8


def stamp() -> str:
    # Full date + ms (the old %H:%M:%S stamps were ambiguous across days).
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}Z"


def is_garbage(raw: bytes) -> bool:
    if len(raw) < GARBAGE_MIN_LEN:
        return False
    nonprint = sum(1 for b in raw if b < 0x20 and b not in (0x09, 0x1B))
    return nonprint / len(raw) >= GARBAGE_RATIO


state = {
    "lock": threading.Lock(),          # serializes command execution
    "rx_lines": deque(maxlen=400),     # (t, line) ring of everything received
    "last_rx_t": 0.0,
    "last_hb_t": 0.0,
    "opened_at": time.time(),
    "journal": None,
    "ser": None,
    # flight recorder
    "seat": "seat",
    "ring": deque(maxlen=RING_LINES),  # (stamp, kind, line)
    "incident_dir": None,
    "snap_tail": 0,                    # lines still to collect post-trigger
    "last_snap_t": 0.0,
    "last_trigger": "",
    "usb_present": None,
}


def record(kind: str, line: str, raw: bytes = b"") -> None:
    """Journal + ring + trigger evaluation for one line of any origin."""
    ts = stamp()
    if state["journal"]:
        state["journal"].write(f"{ts} {kind}: {line}\n")
        state["journal"].flush()
    state["ring"].append((ts, kind, line))
    if state["snap_tail"] > 0:
        state["snap_tail"] -= 1
        if state["snap_tail"] == 0:
            write_snapshot()
    trigger = None
    if kind == "dev":
        for pat in TRIGGER_PATTERNS:
            if pat.search(line):
                trigger = pat.pattern
                break
        if trigger is None and is_garbage(raw or line.encode("latin1")):
            trigger = "garbage-line"
    elif kind in ("stall", "usb-gone", "usb-back"):
        trigger = kind
    if trigger:
        now = time.time()
        if (
            state["snap_tail"] == 0
            and now - state["last_snap_t"] >= SNAPSHOT_COOLDOWN_S
        ) or trigger not in state["last_trigger"]:
            state["last_snap_t"] = now
            state["last_trigger"] = trigger
            state["snap_tail"] = POST_TRIGGER_LINES
            if state["snap_tail"] == 0:
                write_snapshot()


def write_snapshot() -> None:
    d = state["incident_dir"]
    if not d:
        return
    try:
        os.makedirs(d, exist_ok=True)
        state["snap_seq"] = state.get("snap_seq", 0) + 1
        path = os.path.join(
            d,
            f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{state['snap_seq']:03d}-{state['seat']}.log",
        )
        with open(path, "w") as fh:
            fh.write(
                f"# flight-recorder snapshot seat={state['seat']} trigger={state['last_trigger']!r}\n"
            )
            for ts, kind, line in state["ring"]:
                fh.write(f"{ts} {kind}: {line}\n")
        if state["journal"]:
            state["journal"].write(f"{stamp()} rec: snapshot {path}\n")
    except OSError as e:  # never let the recorder kill the daemon
        print(f"[bolty-console] snapshot failed: {e}", file=sys.stderr, flush=True)


def usb_watch_thread(port_path: str) -> None:
    """Presence tracker: brownouts that reset the BOARD but not its USB
    bridge are invisible in the kernel log (2026-10-26 m5stick POWERON at
    04:55 with zero kernel USB events); this at least dates transitions of
    OUR device path."""
    while True:
        present = os.path.exists(port_path)
        if state["usb_present"] is not None and present != state["usb_present"]:
            record("usb-back" if present else "usb-gone", port_path)
        state["usb_present"] = present
        time.sleep(5.0)


def reader_thread(ser) -> None:
    buf = b""
    stall_deadline = None
    while True:
        try:
            chunk = ser.read(512)
        except serial.SerialException as e:
            # Device vanished (rebind/unplug) or the CDC reads stall
            # ("device reports readiness to read but returned no data").
            # A wedged-but-present device stalls forever: retry on the same
            # fd for STALL_RETRY_S before exiting — see the constant's
            # comment for why reopens must stay rare on the C3.
            now = time.time()
            if stall_deadline is None:
                stall_deadline = now + STALL_RETRY_S
                record("stall", f"read failed, retrying on same fd: {e}")
                print(
                    f"[bolty-console] serial read failed (retrying on same"
                    f" fd for {STALL_RETRY_S:.0f}s): {e}",
                    file=sys.stderr,
                    flush=True,
                )
            elif now > stall_deadline:
                print(
                    f"[bolty-console] serial read still failing after"
                    f" {STALL_RETRY_S:.0f}s: exiting for a systemd reopen"
                    " (NOTE: reopen pulses DTR/RTS = C3 board reset)",
                    file=sys.stderr,
                    flush=True,
                )
                os._exit(3)
            time.sleep(1.0)
            continue
        stall_deadline = None
        if not chunk:
            continue
        state["last_rx_t"] = time.time()
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.rstrip(b"\r").decode("latin1", "replace")
            if line:
                state["rx_lines"].append((time.time(), line))
                if line.startswith("[HB]"):
                    state["last_hb_t"] = time.time()
                record("dev", line, raw=raw)


def capture_since(t0: float):
    return [l for (t, l) in state["rx_lines"] if t >= t0]


def handle_conn(conn: socket.socket) -> None:
    try:
        conn.settimeout(5)
        data = b""
        while b"\n" not in data:
            c = conn.recv(256)
            if not c:
                break
            data += c
        cmdline = data.decode("latin1", "replace").split("\n", 1)[0].strip()
        if not cmdline:
            return

        if cmdline == "PING":
            now = time.time()
            age = int(now - state["last_hb_t"]) if state["last_hb_t"] else -1
            resp = [f"alive hb_age={age}s opened={int(now - state['opened_at'])}s ago"]
            resp.extend(capture_since(now - 3))
            conn.sendall(("\n".join(resp) + "\nOK\n").encode())
            return

        parts = cmdline.split()
        if parts and parts[0].upper() == "RAW":
            secs = min(float(parts[1]) if len(parts) > 1 else 5.0, 60.0)
            t0 = time.time()
            time.sleep(secs)
            resp = capture_since(t0)
            conn.sendall(("\n".join(resp) + f"\nOK {len(resp)} lines\n").encode())
            return

        with state["lock"]:
            t0 = time.time()
            state["ser"].reset_input_buffer()
            state["ser"].write((cmdline + "\r\n").encode())
            state["ser"].flush()
            deadline = t0 + HARD_CAP_S
            n = 0
            while time.time() < deadline:
                time.sleep(0.15)
                n = len(capture_since(t0))
                if n and (time.time() - state["last_rx_t"]) >= QUIET_S:
                    break
            resp = capture_since(t0)
        conn.sendall(("\n".join(resp) + f"\nOK {len(resp)} lines\n").encode())
    except Exception as e:  # noqa: BLE001 — daemon must never die on a client
        try:
            conn.sendall(f"ERR {e}\n".encode())
        except OSError:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=DEFAULT_PORT)
    ap.add_argument("--socket", default="/run/bolty/console.sock")
    ap.add_argument("--log", default=os.path.expanduser("~/.bolty/console.log"))
    ap.add_argument("--seat", default="seat", help="seat name for incident snapshots")
    ap.add_argument(
        "--incident-dir",
        default="/root/bench/incidents",
        help="flight-recorder snapshot directory (kept OUTSIDE the repo: "
        "raw logs never go to GitHub — owner directive 2026-10-19)",
    )
    args = ap.parse_args()

    state["seat"] = args.seat
    state["incident_dir"] = args.incident_dir
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    state["journal"] = open(args.log, "a", buffering=1)

    ser = serial.Serial(args.port, 115200, bytesize=8, parity="N", stopbits=2, timeout=0.1)
    # Settle control lines ONCE to neutral (DTR asserted on open holds IO0 low on
    # this board family -> download mode -> silent UART). No further toggling (B11).
    ser.dtr = False
    ser.rts = False
    state["ser"] = ser  # NOTE: opened once; DTR/RTS are never touched again (B11)
    threading.Thread(target=reader_thread, args=(ser,), daemon=True).start()
    threading.Thread(target=usb_watch_thread, args=(args.port,), daemon=True).start()
    record("host", f"daemon opened {args.port} seat={args.seat}")

    sock_path = args.socket
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(8)
    print(f"[bolty-console] serving {sock_path} for {args.port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
