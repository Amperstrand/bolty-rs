#!/usr/bin/env python3
"""HIL: full burn -> inspect -> live-worker tap -> wipe -> blank cycle.

Proves the complete card lifecycle on real hardware through the
bolty-console daemon (never opens the tty — that wedges the FT232 bridge;
see docs/lessons-learned.md B11).

Key configuration lesson (B12): boltcardpoc.psbt.me can only route an
ANONYMOUS tap via deterministic keys (it needs the UID to pick a percard
CSV row, and needs the row to decrypt the UID). Default burn mode is
therefore the public deterministic issuer key. --keys (percard) burns are
cryptographically valid but only usable where the reader knows the keys.

Usage:
  python3 tools/hil/burn_cycle.py                     # deterministic burn
  python3 tools/hil/burn_cycle.py --issuer <32hex>    # custom issuer key
  python3 tools/hil/burn_cycle.py --keys "k0 k1 k2 k3 k4"  # raw keys burn
  python3 tools/hil/burn_cycle.py --skip-wipe         # leave card in service
Exit 0 only if every executed stage passes.
"""
import argparse
import os
import re
import subprocess
import sys

UID_EXPECT = os.environ.get("HIL_UID", "04c474fa967380")
PUBLIC_ISSUER = "0" * 31 + "1"  # well-known public dev issuer key (zeros+1), v1 — NOT a secret
URL = os.environ.get("HIL_URL", "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}")
CTL = os.environ.get("HIL_CTL", "/run/bolty/console.sock")


def ctl(cmd: str) -> str:
    import socket

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(70)
    s.connect(CTL)
    s.sendall((cmd + "\n").encode())
    out = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        out += c
    s.close()
    text = out.decode("latin1", "replace")
    lines = text.splitlines()
    if not lines or not lines[-1].startswith("OK"):
        raise RuntimeError(f"console command failed: {cmd!r} -> {text!r}")
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--issuer", default=PUBLIC_ISSUER, help="issuer key hex (default: public deterministic v1)")
    ap.add_argument("--keys", help="raw per-card keys 'k0 k1 k2 k3 k4' (overrides --issuer)")
    ap.add_argument("--percard", action="store_true",
                    help="burn with percard keys from HIL_PERCARD_KEYS env ('k0 k1 k2 k3 k4') "
                         "and expect the worker to route the anonymous tap via its percard "
                         "K1 fallback (ENABLE_PERCARD_FALLBACK, docs/percard-fallback.md)")
    ap.add_argument("--skip-burn", action="store_true")
    ap.add_argument("--skip-wipe", action="store_true")
    args = ap.parse_args()

    print("=== PING (daemon health) ===")
    print(ctl("PING"))

    print("=== uid (expect our card) ===")
    uid = ctl("uid").lower()
    if UID_EXPECT not in uid:
        print(f"FAIL: expected {UID_EXPECT}, got: {uid}")
        return 2

    results = {}
    if args.percard:
        import os
        percard_keys = os.environ.get("HIL_PERCARD_KEYS", "").strip()
        if not percard_keys or len(percard_keys.split()) != 5:
            print("FAIL: --percard requires HIL_PERCARD_KEYS='k0 k1 k2 k3 k4' (source: worker keys/ CSV)")
            return 2
        args.keys = percard_keys
    if not args.skip_burn:
        print("=== stage + burn ===")
        if args.keys:
            ctl("keys " + args.keys)
        else:
            ctl(f"issuer {args.issuer}")
        ctl(f"url {URL}")
        burn = ctl("burn")
        results["burn"] = "fail" not in burn.lower() and "error" not in burn.lower()

    insp = ctl("inspect")
    results["inspect_provisioned"] = "provisioned" in insp.lower()

    picc = ctl("picc")
    results["picc_sdm_ok"] = "sdm=ok" in picc.lower() and "uid_match=true" in picc.lower()

    m_p = re.search(r"p=([0-9A-Fa-f]{32})", picc)
    m_c = re.search(r"c=([0-9A-Fa-f]{16})", picc)
    tap_url = f"{URL.split('?')[0]}?p={m_p.group(1)}&c={m_c.group(1)}" if (m_p and m_c) else ""
    print("TAP_URL:", tap_url)
    if tap_url:
        p = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20", tap_url],
            capture_output=True, text=True, timeout=30,
        )
        print("worker tap HTTP:", p.stdout.strip())
        results["worker_tap_200"] = p.stdout.strip() == "200"
    else:
        results["worker_tap_200"] = False

    if not args.skip_wipe:
        wipe = ctl("wipe")
        results["wipe"] = "fail" not in wipe.lower() and "error" not in wipe.lower()
        insp2 = ctl("inspect")
        results["inspect_blank"] = "blank" in insp2.lower()

    print("\n===== CYCLE SUMMARY =====")
    for k, v in results.items():
        print(f"  {k:24s}: {'PASS' if v else 'FAIL'}")
    print("TAP_URL:", tap_url)
    ok = all(results.values())
    print("RESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
