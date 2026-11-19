#!/usr/bin/env python3
"""Issue #272 contention emulator: append byte-realistic audit lines to
/tmp/bolty-audit.log with O_APPEND, mimicking a live bench process
(nucula_cycle.py / bolty-cli lane) sharing the default audit path.

Line formats copied verbatim from apps/bolty-cli/src/audit.rs:
  banner:  [{ms}] SESSION START pid=P host=H exe=E wall=RFC3339Z
  event:   [{ms}] EVENT  msg [provenance=Tag]
  tx:      [{ms}] TX APDU len=N data=HEX
  rx ok:   [{ms}] RX OK   sw=91AE len=N data=HEX   (note 3 spaces after OK)
Cadence: burst of 2-6 lines every 20-100 ms.
"""
import os, random, socket, time, sys

PATH = "/tmp/bolty-audit.log"
PID = os.getpid()
HOST = socket.gethostname().lower()
random.seed()

def ms():
    return int(time.time() * 1000)

def wall(msv):
    # RFC3339 UTC via time module
    t = time.gmtime(msv // 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", t) + ".%03dZ" % (msv % 1000)

def hexs(b):
    return b.hex().upper()

fd = os.open(PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

def emit(line):
    os.write(fd, (line + "\n").encode())

now = ms()
emit(f"[{now}] SESSION START pid={PID} host={HOST} exe=bench-emulator wall={wall(now)}")

APDUS = [
    (8, bytes.fromhex("9071000005000300000000")),   # auth-first style (shortened)
    (5, bytes.fromhex("9060000000")),
    (12, bytes.fromhex("905A00000500000000000000")),
]
RX_OKS = ["91AE", "91AD", "9000", "91AE", "917E", "91AE"]  # 91AE-heavy: budget spend
EVENTS = [
    "scan-keys: trying k0-issuer-v1",
    "scan-keys: REJECTED k0-issuer-v1",
    "try-key: candidate 1/20 (91ae expected on wrong key)",
    "wipe: SUCCESS — all keys reset to factory zeros [provenance=DerivedIssuer(1)]",
    "burn: SUCCESS — K0 v1, K1-K4 installed [provenance=DerivedIssuer(1)]",
    "budget: host-side accounting report",
    "picc: SDM read ok",
]

try:
    while True:
        n = random.randint(2, 6)
        for _ in range(n):
            now = ms()
            r = random.random()
            if r < 0.45:
                ln, data = random.choice(APDUS)
                emit(f"[{now}] TX APDU len={ln} data={hexs(data)}")
            elif r < 0.75:
                sw = random.choice(RX_OKS)
                emit(f"[{now}] RX OK   sw={sw} len=2 data={sw}")
            else:
                emit(f"[{now}] EVENT  {random.choice(EVENTS)}")
        time.sleep(random.uniform(0.02, 0.1))
except KeyboardInterrupt:
    pass
finally:
    os.close(fd)
