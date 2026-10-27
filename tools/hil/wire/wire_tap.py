#!/usr/bin/env python3
"""wire_tap.py — convert a bolty audit log into structured APDU vectors (JSONL).

Standards applied (researched 2026-10-27, see WIRE-METHODOLOGY.md):
- one JSON object per exchange (cmd APDU + response + status classification)
- NTAG424 status semantics: 91xx SW2 classes per AN12196 / NT4H2421Gx
- masking of session-randomized fields (RndA/RndB/TI/CMACs) for A/B diffs:
  structural fingerprints keep position/length, replace volatile bytes

Usage: wire_tap.py AUDIT_LOG [-o out.jsonl] [--since TS]
"""
import argparse
import json
import re
import sys

TS_RE = re.compile(r"^\[(\d+)\]")
TX_RE = re.compile(r"TX APDU len=(\d+) data=([0-9A-Fa-f]*)")
RX_RE = re.compile(r"RX OK\s+sw=([0-9A-Fa-f]{4})\s+len=(\d+)\s+data=([0-9A-Fa-f]*)")

# fields that are session-randomized; masked in fingerprints
VOLATILE_LEN = {16, 32}  # RndB / cryptogram blocks


def classify_sw(sw: str) -> str:
    sw1, sw2 = int(sw[:2], 16), int(sw[2:], 16)
    if sw1 == 0x90 and sw2 == 0x00:
        return "OK"
    if sw1 == 0x91:
        return {
            0x00: "NTAG-OK",
            0xAF: "ADDITIONAL-FRAME",
            0xAE: "AUTH-ERROR",
            0xAD: "AUTH-DELAY",
            0x1E: "INTEGRITY-ERROR",
            0x03: "LENGTH-ERROR",
            0x27: "FUNCTION-ERROR",
        }.get(sw2, f"NTAG-{sw2:02x}")
    return {"6982": "SECURITY-NOT-SATISFIED", "6a82": "FILE-NOT-FOUND",
            "6d00": "INS-NOT-SUPPORTED", "6e00": "CLA-NOT-SUPPORTED"}.get(sw, f"ISO-{sw}")


def cmd_name(apdu: str) -> str:
    if len(apdu) < 8:
        return "GET-UID-PSEUDO"
    ins = int(apdu[2:4], 16)
    return {
        0x71: "AuthFirst", 0xAF: "AuthSecond/Chain", 0x60: "GetVersion",
        0xF5: "GetFileSettings", 0x5F: "ChangeFileSettings",
        0xAD: "ReadData", 0x8D: "WriteData", 0xC4: "ChangeKey",
        0x64: "GetKeySettings", 0x51: "GetCardUid", 0x52: "SetCardUid",
        0xA4: "ISO-Select", 0xB0: "ISO-ReadBinary", 0xD6: "ISO-UpdateBinary",
        0xCA: "GetUid-Pseudo",
    }.get(ins, f"INS-{ins:02x}")


def fingerprint(apdu: str) -> str:
    """Structural mask: keep header, mask crypto-random bodies."""
    if len(apdu) < 10:
        return apdu
    hdr = apdu[:10]
    body = apdu[10:]
    if len(body) in VOLATILE_LEN or len(body) == 8 * 2:
        return hdr + "<rnd%d>" % (len(body) // 2)
    return hdr + body[:16] + ("..+%d" % (len(body) // 2 - 8) if len(body) > 32 else "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("audit_log")
    ap.add_argument("-o", "--out")
    ap.add_argument("--since", type=int, default=0)
    args = ap.parse_args()

    events = []
    pending_tx = None
    for line in open(args.audit_log, encoding="utf-8", errors="replace"):
        m = TS_RE.match(line)
        ts = int(m.group(1)) if m else (events[-1]["ts"] if events else 0)
        if ts < args.since:
            continue
        tx = TX_RE.search(line)
        if tx:
            pending_tx = {"ts": ts, "len": int(tx.group(1)), "data": tx.group(2).upper()}
            continue
        rx = RX_RE.search(line)
        if rx and pending_tx:
            sw, rlen, rdata = rx.group(1), int(rx.group(2)), rx.group(3).upper()
            events.append({
                "ts": ts, "cmd": cmd_name(pending_tx["data"]),
                "apdu": pending_tx["data"], "apdu_fp": fingerprint(pending_tx["data"]),
                "resp_sw": sw, "resp_class": classify_sw(sw),
                "resp_len": rlen, "resp": rdata,
                "resp_fp": fingerprint(rdata) if rdata else "",
            })
            pending_tx = None

    out = args.out or (args.audit_log.rsplit(".", 1)[0] + ".wire.jsonl")
    with open(out, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    print(f"{len(events)} exchanges -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
