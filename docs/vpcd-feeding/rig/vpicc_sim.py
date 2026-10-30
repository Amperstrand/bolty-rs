#!/usr/bin/env python3
"""
vpicc_sim.py — virtual PICC simulator with selectable protocol conformance.

Modes (official protocol table, vsmartcard API docs):
  spec    : OFF/ON/RESET -> NO response; ATR -> ATR; APDU -> R-APDU   [reference]
  deviant : additionally answers RESET with an ATR (bench convention:
            vpicc_table.py + firmware client_loop answer 0x02)

Every response carries a counter byte so the harness can tell WHICH reply
landed where:  ATR(n) = 3B FF <n> ;  R-APDU(n) = <n> 90 00
"""
import argparse
import socket
import sys
import threading
import time

atr_ctr = 0
r_ctr = 0
log = open(f"vpicc_{time.strftime('%H%M%S')}.log", "w")


def send_frame(sock, payload):
    sock.sendall(len(payload).to_bytes(2, "big") + payload)


def handle(sock, mode):
    global atr_ctr, r_ctr
    buf = b""
    while True:
        while len(buf) < 2:
            d = sock.recv(4096)
            if not d:
                return
            buf += d
        ln = int.from_bytes(buf[:2], "big")
        while len(buf) < 2 + ln:
            d = sock.recv(4096)
            if not d:
                return
            buf += d
        msg, buf = buf[2:2 + ln], buf[2 + ln:]

        if ln == 1:
            c = msg[0]
            if c == 0x04:                      # Get ATR
                atr_ctr += 1
                atr = bytes([0x3B, 0xFF, atr_ctr])
                send_frame(sock, atr)
                log.write(f"{time.time():.6f} CTRL ATR    -> ATR({atr_ctr})\n")
            elif c == 0x02 and mode == "deviant":   # RESET (off-spec reply)
                atr_ctr += 1
                atr = bytes([0x3B, 0xFF, atr_ctr])
                send_frame(sock, atr)
                log.write(f"{time.time():.6f} CTRL RESET  -> ATR({atr_ctr})  [DEVIANT]\n")
            elif c == 0x02 and mode == "zeroack":   # RESET answered with EMPTY frame
                send_frame(sock, b"")
                log.write(f"{time.time():.6f} CTRL RESET  -> 0-length frame  [ZEROACK]\n")
            else:
                log.write(f"{time.time():.6f} CTRL {c:#04x}    -> (silent, per spec)\n")
            log.flush()
            continue

        r_ctr += 1
        r = bytes([r_ctr, 0x90, 0x00])
        send_frame(sock, r)
        log.write(f"{time.time():.6f} APDU {msg.hex()} -> R-APDU({r_ctr})\n")
        log.flush()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--mode", choices=["spec", "deviant", "zeroack"], required=True)
    a = p.parse_args()

    srv = socket.create_connection(("127.0.0.1", a.port))
    conn = srv
    print(f"[vpicc:{a.mode}] connected to {a.port}", flush=True)
    try:
        handle(conn, a.mode)
    finally:
        log.write("connection closed\n")
        log.close()
        conn.close()


if __name__ == "__main__":
    main()
