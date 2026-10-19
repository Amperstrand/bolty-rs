#!/usr/bin/env python3
"""Decode defmt 0.3.100 (defmt-1.0.1 core) rzCOBS RTT frames from a raw
SRAM dump of a bolty-stm32 target.

Why this exists: probe-rs 0.32 run/attach does not print RTT on the
shared F469 bench for WFI-sleeping firmware (see
docs/stm32-bringup-2026-10-19.md). The reliable capture path is
`st-flash read` (halts the core) + this offline decode.

Caveat: defmt-1.x-internal argument encoding carries type-marker bytes
this decoder does not fully model — arg fields of frames with `{}`
placeholders may show marker bytes around the value. Frames without
args decode exactly; the wire bytes are always printed for cross-checks
against tools/hil/rtt/verify_frames.py (forward encoder simulation).

Usage:
  st-flash --serial <stlink> read dump.bin 0x20000000 0x11000
  python3 decode_rtt.py <elf> dump.bin [--buffer-offset 0x1005C]

The ELF provides the tag table (interned strings live in the symbol
table). Buffer offset = the .uninit section address minus 0x20000000
(see `arm-none-eabi-objdump -h <elf> | grep uninit`).
"""
import argparse
import json
import re
import struct
import subprocess
import sys


def rzcobs_frames(buf):
    frames, cur, i = [], [], 0
    while i < len(buf):
        b = buf[i]
        i += 1
        if b == 0x00:
            if cur:
                frames.append(bytes(cur))
                cur = []
            continue
        if b <= 0x7F:
            for k in range(7):
                if (b >> k) & 1 == 0:
                    if i < len(buf):
                        cur.append(buf[i])
                        i += 1
                else:
                    cur.append(0)
        elif b == 0xFF:
            for _ in range(134):
                if i < len(buf):
                    cur.append(buf[i])
                    i += 1
            cur.append(0)
        else:
            for _ in range((b - 0x80) + 7):
                if i < len(buf):
                    cur.append(buf[i])
                    i += 1
            cur.append(0)
    if cur:
        frames.append(bytes(cur))
    return frames


def tag_table(elf):
    symtab = subprocess.run(
        ["readelf", "-sW", elf], capture_output=True, text=True, errors="replace"
    ).stdout
    tags = {}
    for line in symtab.splitlines():
        m = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+OBJECT\s+\w+\s+\w+\s+\d+\s+(\{.*\})", line
        )
        if m:
            try:
                j = json.loads(m.group(2))
                if "tag" in j and "data" in j:
                    tags[int(m.group(1), 16)] = (j["tag"], j["data"])
            except Exception:
                pass
    return tags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("dump")
    ap.add_argument("--buffer-offset", type=lambda x: int(x, 0), default=None)
    args = ap.parse_args()

    data = open(args.dump, "rb").read()
    magic = data[0x08:0x18]
    if not magic.startswith(b"SEGGER RTT"):
        sys.exit("no RTT control block magic at 0x20000008 — stale dump?")
    size, write, read, flags = struct.unpack_from("<IIII", data, 0x28)

    if args.buffer_offset is None:
        out = subprocess.run(
            ["arm-none-eabi-objdump", "-h", args.elf],
            capture_output=True, text=True, errors="replace",
        ).stdout
        m = re.search(r"\.uninit\s+[0-9a-f]+\s+([0-9a-f]+)", out)
        if not m:
            sys.exit("could not locate .uninit in the ELF — pass --buffer-offset")
        args.buffer_offset = int(m.group(1), 16) - 0x20000000

    print(
        f"header: magic={magic!r} size={size} write={write} read={read} "
        f"flags={flags} buffer-off=0x{args.buffer_offset:x}"
    )
    buf = data[args.buffer_offset : args.buffer_offset + size]
    tags = tag_table(args.elf)
    print(f"tag table: {len(tags)} entries")

    for f in rzcobs_frames(buf):
        if len(f) < 2:
            continue
        tag = struct.unpack_from("<H", f, 0)[0]
        ts = struct.unpack_from("<Q", f, 2)[0] if len(f) >= 10 else None
        info = tags.get(tag, ("UNKNOWN", "?"))
        rest = f[10:].hex() if len(f) >= 10 else ""
        print(f"ts={ts} [{info[0]}] {info[1]!r} arg-bytes={rest}")


if __name__ == "__main__":
    main()
