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
"""
import argparse
import os
import socket
import sys
import threading
import time
from collections import deque

import serial

DEFAULT_PORT = "/dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0"
QUIET_S = 1.0
HARD_CAP_S = 40.0

state = {
    "lock": threading.Lock(),          # serializes command execution
    "rx_lines": deque(maxlen=400),     # (t, line) ring of everything received
    "last_rx_t": 0.0,
    "last_hb_t": 0.0,
    "opened_at": time.time(),
    "journal": None,
    "ser": None,
}


def journal(line: str) -> None:
    if state["journal"]:
        state["journal"].write(f"{time.strftime('%H:%M:%S')} {line}\n")
        state["journal"].flush()


def reader_thread(ser) -> None:
    buf = b""
    while True:
        try:
            chunk = ser.read(512)
        except serial.SerialException as e:
            # Device vanished (rebind/unplug). Exit; systemd Restart=always
            # reopens when the device unit returns.
            print(f"[bolty-console] serial read failed: {e}", file=sys.stderr, flush=True)
            os._exit(3)
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
                journal(line)


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
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    state["journal"] = open(args.log, "a", buffering=1)

    ser = serial.Serial(args.port, 115200, bytesize=8, parity="N", stopbits=2, timeout=0.1)
    state["ser"] = ser  # NOTE: opened once; DTR/RTS are never touched again (B11)
    threading.Thread(target=reader_thread, args=(ser,), daemon=True).start()

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
