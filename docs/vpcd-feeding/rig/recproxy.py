#!/usr/bin/env python3
"""
recproxy.py — recording TCP proxy that synthesizes a Wireshark-decodable pcap.

Chain:  [driver :Pd (listens)] <- [proxy] <- [real vpicc :Pp (connects to proxy)]
The proxy connects to the driver's listener (impersonating the vpicc side of the
socket) and accepts the real vpicc on its own listener. Every relayed chunk is
written as a full IPv4+TCP packet record (LINKTYPE_RAW / DLT 101).

Checksums are written as 0 — Wireshark flags but decodes them fine.
"""
import argparse
import socket
import struct
import threading
import time


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        # magic, v2.4, tz, sigfigs, snaplen, LINKTYPE_RAW(101)
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        self.f.flush()

    def packet(self, ts, src_port, dst_port, payload, seq):
        tcp = struct.pack("!HHIIBBHHH",
                          src_port, dst_port, seq, 0,          # sport dport seq ack
                          5 << 4,                              # data offset 5 words
                          0x18,                                # PSH|ACK
                          8192, 0, 0)                          # window, cksum=0, urg
        total = 20 + len(tcp) + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total, 0x1234, 0x4000, 64, 6, 0,
                         socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
        frame = ip + tcp + payload
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)
        self.f.flush()


def relay(src, dst, writer, sport, dport, seq_box, tag):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            writer.packet(time.time(), sport, dport, data, seq_box[0])
            seq_box[0] += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, required=True, help="port for the real vpicc")
    p.add_argument("--driver", type=int, required=True, help="driver's listening port")
    p.add_argument("--out", required=True)
    a = p.parse_args()

    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up.connect(("127.0.0.1", a.driver))          # proxy -> driver (vpicc role)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.listen))
    srv.listen(1)
    print(f"[proxy] connected to driver :{a.driver}; waiting vpicc on :{a.listen}", flush=True)
    down, _ = srv.accept()                        # real vpicc -> proxy
    print("[proxy] vpicc connected, recording", flush=True)

    w = PcapWriter(a.out)
    seq_up = [1000]      # proxy -> driver direction
    seq_dn = [5000]      # vpicc -> proxy -> driver responses share the driver-facing
    t1 = threading.Thread(target=relay, args=(down, up, w, a.listen, a.driver, seq_up, "up"))
    t2 = threading.Thread(target=relay, args=(up, down, w, a.driver, a.listen, seq_dn, "dn"))
    t1.start(); t2.start(); t1.join(); t2.join()
    print(f"[proxy] done, pcap: {a.out}", flush=True)


if __name__ == "__main__":
    main()
