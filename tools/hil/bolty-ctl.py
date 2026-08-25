#!/usr/bin/env python3
"""bolty-ctl — talk to the bolty-console daemon (never to the tty directly).

Usage: bolty-ctl <command...>     e.g. bolty-ctl status
       bolty-ctl PING
       bolty-ctl RAW 10
Exit 0 on OK, non-zero otherwise. Output lines are printed verbatim.
"""
import socket
import sys

SOCK = "/run/bolty/console.sock"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = " ".join(sys.argv[1:])
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(70)
    s.connect(SOCK)
    s.sendall((cmd + "\n").encode())
    chunks = []
    while True:
        try:
            c = s.recv(4096)
        except socket.timeout:
            print("ERR timeout", file=sys.stderr)
            return 3
        if not c:
            break
        chunks.append(c)
    out = b"".join(chunks).decode("latin1", "replace")
    lines = out.splitlines()
    ok = bool(lines) and lines[-1].startswith("OK")
    for l in lines:
        print(l)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
