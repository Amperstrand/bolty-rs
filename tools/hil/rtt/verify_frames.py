#!/usr/bin/env python3
"""Forward rzCOBS encoder simulation (ported 1:1 from
defmt-1.0.1/src/encoding/rzcobs.rs) to verify decoded frames
byte-exactly against observed RTT wire bytes.

The decoder in decode_rtt.py can mis-split defmt's internal argument
encoding; when a frame's meaning matters, simulate the expected
plaintext here and compare against the raw buffer prefix.

Usage:
  python3 verify_frames.py <dump.bin> <plaintext-hex> [<plaintext-hex> ...]

Each plaintext is one frame's decoded bytes: [tag u16 LE][ts u64 LE]
[args...]. Tag numbers come from decode_rtt.py's tag table. The script
prints the simulated wire bytes for the frame sequence and whether the
dump's RTT buffer starts with them.
"""
import argparse
import struct
import sys


class Enc:
    def __init__(self):
        self.run = 0
        self.zeros = 0
        self.started = False
        self.out = bytearray()

    def w(self, b):
        self.out.append(b)

    def start_frame(self):
        if not self.started:
            self.started = True
            self.w(0x00)

    def end_frame(self):
        if self.run == 0:
            pass
        elif 1 <= self.run <= 6:
            self.w((self.zeros | (0xFF << self.run)) & 0x7F)
        else:
            self.w((self.run - 7) | 0x80)
        self.w(0x00)
        self.run = 0
        self.zeros = 0

    def write(self, bs):
        for byte in bs:
            if self.run < 7:
                if byte == 0:
                    self.zeros |= 1 << self.run
                else:
                    self.w(byte)
                self.run += 1
                if self.run == 7 and self.zeros != 0x00:
                    self.w(self.zeros)
                    self.run = 0
                    self.zeros = 0
            elif byte == 0:
                self.w((self.run - 7) | 0x80)
                self.run = 0
                self.zeros = 0
            else:
                self.w(byte)
                self.run += 1
                if self.run == 134:
                    self.w(0xFF)
                    self.run = 0
                    self.zeros = 0


def simulate(plaintexts):
    e = Enc()
    for p in plaintexts:
        e.start_frame()
        e.write(p)
        e.end_frame()
    return bytes(e.out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("plaintexts", nargs="+", help="frame plaintext hex")
    ap.add_argument("--buffer-offset", type=lambda x: int(x, 0), default=0x1005C)
    args = ap.parse_args()

    frames = [bytes.fromhex(p) for p in args.plaintexts]
    wire = simulate(frames)
    print("simulated wire (%d B): %s" % (len(wire), wire.hex()))

    data = open(args.dump, "rb").read()
    buf = data[args.buffer_offset :]
    ok = buf[: len(wire)] == wire
    print("observed prefix      : %s" % buf[: len(wire) + 4].hex())
    print("MATCH:", ok)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
