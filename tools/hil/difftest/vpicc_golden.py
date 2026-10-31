#!/usr/bin/env python3
"""vpicc_golden — replay a difftest golden capture over vpcd (#261 tier-a class).

A software PICC that connects OUT to a vpcd listener (pcscd side) and
answers C-APDUs from a recorded golden capture (results/golden_acr1252.json)
instead of a fixed table — the exact exchanges a real NTAG424 produced on
the ACR1252, in order, repeats included.

Why: the difftest goldens are hardware-coupled (a specific burn card on a
specific reader). This vpicc makes the recorded card behavior available on
ANY host with pcscd+vpcd — the acr-only golden sanity, capture-tool
regression tests, and host-stack smoke can run with zero hardware and zero
card-safety exposure. It is a REPLAY (canned responses), not a model: it
proves the pcsc→vpcd→harness path, and serves as the chassis a stateful
NTAG424 model can plug into later (swap the queue lookup for real logic).

Wire protocol (vsmartcard vpcd; mirrored from vpicc_table.py / firmware
client_loop): 2-byte big-endian length + payload. 1-byte controls:
0x02/0x04 (RESET/ATR) → answer the golden ATR; 0x00/0x01 (OFF/ON) → NO
reply (an empty ack de-syncs the driver's next ATR probe → permanent
eject). APDU → next queued answer for that exact command bytes.

Lookup discipline: the golden records repeats of the same APDU with
DIFFERENT answers (auth-delay ladders: same command, 91AD then 91AE), so
each command maps to an ordered QUEUE consumed one per request. An APDU
absent from the golden answers 6D00 (instruction not supported) and is
logged — never silently matched by prefix.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from collections import deque
from pathlib import Path

DEFAULT_GOLDEN = Path(__file__).parent / "results" / "golden_acr1252.json"
UNKNOWN_RESPONSE = b"\x6d\x00"


def load_queues(golden_path: Path) -> tuple[str, dict[bytes, deque[bytes]]]:
    """Return (atr_hex, {c_apdu: deque of r_apdus}) from a golden capture."""
    g = json.loads(golden_path.read_text())
    atr = g.get("card_atr", "").replace(" ", "")
    queues: dict[bytes, deque[bytes]] = {}
    order: list[bytes] = []
    for r in g.get("results", []):
        capdu = (r.get("apdu_hex") or "").replace(" ", "")
        if not capdu:
            continue  # specials (atr_on_connect, reconnect_atr) have no C-APDU
        key = bytes.fromhex(capdu)
        data = bytes.fromhex((r.get("response_bytes") or ""))
        sw = bytes.fromhex((r.get("sw") or "6d00"))
        if key not in queues:
            queues[key] = deque()
            order.append(key)
        queues[key].append(data + sw)
    return atr, queues


class GoldenVpicc(threading.Thread):
    """Connects out to a vpcd listener and serves golden answers in order.

    daemon=True; .stop() ends the reconnect loop. ``answered_probe`` is set
    when the first ATR control has been served (readiness signal).
    ``mismatches`` records unknown C-APDUs (hex strings) for assertions.

    ``answerer`` (optional): any object with ``.answer(capdu) -> bytes``
    replaces the golden-queue lookup — this is how vpicc_model.ModelVpicc
    plugs in (stateful rules instead of canned queues).
    """

    def __init__(self, host: str, port: int, atr: bytes,
                 queues: dict[bytes, deque[bytes]] | None = None,
                 answerer=None):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.atr = atr
        self.queues = queues or {}
        self.answerer = answerer
        self._stop = threading.Event()
        self.apdus_seen: list[bytes] = []
        self.answered_probe = threading.Event()
        self.mismatches: list[str] = []

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:  # pragma: no cover - exercised via pytest
        while not self._stop.is_set():
            try:
                import socket
                sock = socket.create_connection((self.host, self.port),
                                                timeout=2)
            except OSError:
                time.sleep(0.2)
                continue
            try:
                self._session(sock)
            except OSError:
                pass
            finally:
                sock.close()
            time.sleep(0.1)

    def _session(self, sock) -> None:
        import socket as s
        sock.settimeout(5.0)
        buf = b""
        while not self._stop.is_set():
            try:
                chunk = sock.recv(4096)
            except s.timeout:
                continue
            if not chunk:
                return
            buf += chunk
            while len(buf) >= 2:
                n = int.from_bytes(buf[:2], "big")
                if len(buf) < 2 + n:
                    break
                msg, buf = buf[2:2 + n], buf[2 + n:]
                self._handle(sock, msg)

    def _handle(self, sock, msg: bytes) -> None:
        if len(msg) == 1:
            if msg[0] in (0x02, 0x04):
                self._send(sock, self.atr)
                self.answered_probe.set()
            # OFF/ON: no reply (see module docstring)
            return
        self.apdus_seen.append(msg)
        if self.answerer is not None:
            self._send(sock, self.answerer.answer(msg))
            return
        q = self.queues.get(msg)
        if q:
            self._send(sock, q.popleft())
        else:
            self.mismatches.append(msg.hex())
            self._send(sock, UNKNOWN_RESPONSE)

    @staticmethod
    def _send(sock, payload: bytes) -> None:
        sock.sendall(len(payload).to_bytes(2, "big") + payload)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=35970,
                    help="vpcd slot port (35970 = table-card entry)")
    ap.add_argument("--golden", type=Path, default=DEFAULT_GOLDEN)
    args = ap.parse_args()
    atr_hex, queues = load_queues(args.golden)
    n = sum(len(q) for q in queues.values())
    card = GoldenVpicc(args.host, args.port, bytes.fromhex(atr_hex), queues)
    card.start()
    print(f"vpicc_golden: serving {args.host}:{args.port} "
          f"(ATR {atr_hex}, {n} queued answers), Ctrl-C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        card.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
