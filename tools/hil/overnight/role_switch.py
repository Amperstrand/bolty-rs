#!/usr/bin/env python3
"""Mid-night role-switch gate (plan todo 15).

Mirrors ccid-firmware-rs/tools/switch_role.sh — the proven no-wedge flash
path — using PREBUILT merged images only. No cargo invocation ever runs
here: 3am builds are a whole failure class (env/toolchain/target-dir
locks), eliminated by task 4's sha256-stamped images.

Staged-conf strategy (task-1 execution finding): pcscd parses EVERY file
in /etc/reader.conf.d INCLUDING `.disabled` suffixes and then probes the
stick's serial port — a B11 wedge-class DTR/RTS toggle on every pcscd
start. The canonical reader.conf therefore lives OUTSIDE that directory,
staged at tools/hil/overnight/results/images/esp32-ccid.conf, and
placement is explicit per role:

    ccid window : /etc/reader.conf.d/esp32-ccid    PRESENT (sudo cp from staged)
    bolty window: /etc/reader.conf.d/esp32-ccid*   ABSENT  (never `.disabled`)

``ensure_staged()`` (run at the start of every switch; idempotent) moves
any existing /etc/reader.conf.d/esp32-ccid[.disabled] to the staging path
(copying the repo reader.conf there if the staging file is missing) and
fails closed if any esp32-ccid* file survives in /etc/reader.conf.d.

Mechanism per direction (exact sequences via ``dry_graph()``):

    ccid : stop bolty-console -> sudo cp staged -> /etc/reader.conf.d/
           esp32-ccid -> stop pcscd -> esptool @115200 --after no-reset
           write-flash 0x0 esp32-ccid-merged.bin -> rts_pulse_reset ->
           usb_rescan (1-1 unbind/bind) -> pcscd restart + once-retry ->
           STRICT verify: readers() has BOTH "GemPCTwin serial" AND an
           ACR1252 entry.

    bolty: stop port holders -> rm conf (ABSENT) -> stop pcscd -> flash
           bolty-merged.bin (same pulse + rescan) -> pcscd restart (conf
           absent => no stick-port probe) -> start bolty-console ->
           STRICT verify: readers() has ACR1252 and NO GemPC entry, AND
           console PING alive.

bolty-merged.bin embeds the repo partitions.csv (factory @ 0x1E0000 +
otadata/ota_0; task-4 note) — both images flash as-is at 0x0, never
repartitioned. NVS EXPECTATION (Metis): a merged image at 0x0 spans the
NVS region (table @0x8000, NVS @0x9000), so EVERY reflash factory-resets
NVS — WiFi, cert, REST token, otakey, crashlog/bootcnt. switch-to-ccid
needs no WiFi; crashlog monitoring treats each switch as a NEW EPOCH;
task 18 provisions strictly AFTER the final flash of the evening.

Images are resolved from results/images/MANIFEST.json and sha256-verified
BEFORE any flash; a mismatch aborts with zero hardware steps executed
(and no restore reflash — the device was never touched).

Wedge ladder (flash/verify failure, per direction): retry usb_rescan once
-> USBDEVFS_RESET ioctl (``usb_reset_ioctl``) on the stick's /dev/bus/usb
path once -> give up that direction. ``switch_with_fallback()`` makes
<=2 attempts, then best-effort restores the bolty role and returns the
Mode B decision; success returns Mode A.

Integration: overnight.py's ROLE_GATE calls ``switch_with_fallback(
"ccid", ctx=...)``. The ctx is the todo-5 duck-typed PhaseContext
(.row/.anomaly) — every step becomes a timeline row persisted
incrementally by the orchestrator's ResultsStore (write-temp+rename).
Without a ctx, pass ``results_dir=`` for the same atomic incremental
persistence into role_switch_timeline.json. ``switch_to(role, ctx)``
returns a SwitchResult carrying .ok/.detail so it also drop-in satisfies
the orchestrator's GateResult seam.

Standalone (never flashes — the live round-trip is todo 18's rehearsal):

    python3 role_switch.py --graph ccid|bolty   # print the exact sequence
    python3 role_switch.py --selftest           # offline unit paths
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

__all__ = [
    "ROLES",
    "STICK_PORT",
    "STAGED_CONF",
    "ImageVerificationError",
    "StagingError",
    "SwitchResult",
    "RoleSwitcher",
    "ccid_readers_ok",
    "bolty_readers_ok",
    "dry_graph",
    "ensure_staged",
    "switch_to",
    "switch_with_fallback",
    "role_gate",
    "restore_gate",
    "rts_pulse_reset",
    "usb_reset_ioctl",
    "stick_usb_bus_path",
    "ping_console",
    "list_readers",
    "selftest",
    "main",
]

# ------------------------------------------------------------------ paths ----

OVERNIGHT_DIR = Path(__file__).resolve().parent
BOLTY_REPO = OVERNIGHT_DIR.parents[2]
SRC_DIR = BOLTY_REPO.parent
RESULTS_DIR = OVERNIGHT_DIR / "results"
IMAGES_DIR = RESULTS_DIR / "images"
STAGED_CONF = IMAGES_DIR / "esp32-ccid.conf"
REPO_READER_CONF = (Path(os.environ.get("CCID_REPO", SRC_DIR / "ccid-firmware-rs"))
                    / "firmware" / "esp32-ccid" / "reader.conf")

STICK_PORT = "/dev/serial/by-id/usb-Hades2001_M5stack_49D6163EBE-if00-port0"
CONF_DIR = Path("/etc/reader.conf.d")
CONF_ACTIVE = "esp32-ccid"
CONF_DISABLED = "esp32-ccid.disabled"
PCSCD_COMM = "/var/run/pcscd/pcscd.comm"
BOLTY_CTL = OVERNIGHT_DIR.parent / "bolty-ctl.py"

STICK_USB_ID = "0403:6001"  # FT232 UART bridge on the M5Stick (task-1 lsusb)
USBDEVFS_RESET = 21780  # _IOR('U', 20, int) — the classic usbreset ioctl

MANIFEST_NAME = "MANIFEST.json"
IMAGE_FOR_ROLE = {  # role -> (merged bin name, MANIFEST sha256 key)
    "ccid": ("esp32-ccid-merged.bin", "ccid_merged_sha256"),
    "bolty": ("bolty-merged.bin", "bolty_merged_sha256"),
}
ROLES = ("ccid", "bolty")

ESPTOOL_TIMEOUT_S = 900.0   # 4 MB merged image @115200
SYSTEMCTL_TIMEOUT_S = 90.0
TEE_TIMEOUT_S = 30.0
PING_TIMEOUT_S = 30.0
UNBIND_SLEEP_S = 4.0        # switch_role.sh:29
BIND_SLEEP_S = 6.0          # switch_role.sh:30
PCSCD_SETTLE_S = 10.0       # switch_role.sh:66
PCSCD_RETRY_SETTLE_S = 8.0  # switch_role.sh:69
CONSOLE_START_S = 6.0       # switch_role.sh:88


class RoleSwitchError(Exception):
    pass


class ImageVerificationError(RoleSwitchError):
    pass


class StagingError(RoleSwitchError):
    pass


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------ real deps ----

@dataclass
class ProcResult:
    rc: int = 0
    stdout: str = ""
    stderr: str = ""


def _real_run(argv, *, input=None, timeout=None):  # noqa: A002
    try:
        cp = subprocess.run([str(a) for a in argv], input=input,
                            capture_output=True, timeout=timeout)
        return ProcResult(rc=cp.returncode,
                          stdout=cp.stdout.decode("latin1", "replace"),
                          stderr=cp.stderr.decode("latin1", "replace"))
    except subprocess.TimeoutExpired as e:
        return ProcResult(rc=124, stderr=f"timeout after {timeout}s: {e!r}")


def list_readers() -> list:
    """pyscard readers() as plain strings (lazy import — unit paths never
    need pyscard installed)."""
    from smartcard.System import readers
    return [str(r) for r in readers()]


def ping_console(timeout: float = PING_TIMEOUT_S):
    """bolty-ctl PING — the canonical daemon liveness probe."""
    try:
        cp = subprocess.run(["python3", str(BOLTY_CTL), "PING"],
                            capture_output=True, timeout=timeout)
        out = cp.stdout.decode("latin1", "replace")
        return cp.returncode == 0 and "alive" in out, out
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, repr(e)


def rts_pulse_reset(port: str) -> None:
    """Reboot the stick without wedging the FT232 bridge.

    VERBATIM mechanism from ccid-firmware-rs/tools/switch_role.sh:31-37:
    DTR MUST be cleared before the RTS pulse — pyserial asserts DTR on
    open, and DTR=IO0 low + RTS pulse holds the chip in download mode
    (dead-silent UART). This single detail was the entire "frozen
    firmware" afternoon; do not "simplify" it.
    """
    import serial  # lazy — graph/selftest paths never need pyserial
    s = serial.Serial(port, 115200, bytesize=8, parity="N", stopbits=2, timeout=0.2)
    s.dtr = False
    s.rts = False
    time.sleep(0.3)
    s.rts = True
    time.sleep(0.15)
    s.rts = False
    s.close()


def stick_usb_bus_path() -> str:
    """/dev/bus/usb path of the FT232 (0403:6001) from lsusb — wedge-ladder
    rung 2 needs the usbdevfs node, not the tty."""
    cp = subprocess.run(["lsusb"], capture_output=True, timeout=15)
    m = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+" + STICK_USB_ID,
                  cp.stdout.decode("latin1", "replace"))
    if not m:
        raise RuntimeError(f"FT232 {STICK_USB_ID} not found in lsusb output")
    return "/dev/bus/usb/{:03d}/{:03d}".format(int(m.group(1)), int(m.group(2)))


def usb_reset_ioctl(bus_path: str) -> None:
    """USBDEVFS_RESET on the stick's /dev/bus/usb node — the usbreset ioctl
    implemented as a tiny in-process helper (no compiled usbreset binary
    dependency; needs root via the sudo-less opened fd only when run as
    root — the overnight rig runs with NOPASSWD sudo, so callers wrap the
    whole gate anyway)."""
    fd = os.open(bus_path, os.O_WRONLY)
    try:
        fcntl.ioctl(fd, USBDEVFS_RESET, 0)
    finally:
        os.close(fd)


@dataclass
class Deps:
    """Every hardware surface, injectable. Unit tests substitute all of
    these; production uses default_deps()."""
    runner: Callable = _real_run
    readers: Callable = list_readers
    ping: Callable = ping_console
    pulse: Callable = rts_pulse_reset
    usb_bus_path: Callable = stick_usb_bus_path
    usb_reset: Callable = usb_reset_ioctl
    sleep: Callable = time.sleep


# ------------------------------------------------------- verify predicates ----
# The strict role-specific verify (Metis: switch_role.sh's own "any reader"
# check is too weak). Graph `expect` blocks encode the same literals.

def ccid_readers_ok(names: list) -> bool:
    j = " | ".join(names).lower()
    return "gempctwin serial" in j and "acr1252" in j


def bolty_readers_ok(names: list) -> bool:
    j = " | ".join(names).lower()
    return "acr1252" in j and "gempc" not in j


def _check_expect(expect: dict, names: list):
    j = " | ".join(names).lower()
    missing = [i for i in expect.get("includes", []) if i.lower() not in j]
    forbidden = [e for e in expect.get("excludes", []) if e.lower() in j]
    why = f"missing={missing} forbidden_present={forbidden} readers={list(names)[:4]}"
    return not missing and not forbidden, why


# ------------------------------------------------------------- dry graph ----

def _cmd(argv, *, label, input=None, tolerant=False, timeout=SYSTEMCTL_TIMEOUT_S):  # noqa: A002
    return {"kind": "cmd", "argv": [str(a) for a in argv], "label": label,
            "input": input, "tolerant": tolerant, "timeout": timeout}


def _sleep(s: float, label: str) -> dict:
    return {"kind": "sleep", "s": s, "label": label}


def _rescan_steps() -> list:
    # usb_rescan per switch_role.sh:27-31 — whole root port 1-1 (ACR1252
    # disruption window; orchestrator aware-pauses Track B around this).
    return [
        _cmd(["sudo", "tee", "/sys/bus/usb/drivers/usb/unbind"],
             label="usb_rescan unbind 1-1", input=b"1-1", timeout=TEE_TIMEOUT_S),
        _sleep(UNBIND_SLEEP_S, "post-unbind settle"),
        _cmd(["sudo", "tee", "/sys/bus/usb/drivers/usb/bind"],
             label="usb_rescan bind 1-1", input=b"1-1", timeout=TEE_TIMEOUT_S),
        _sleep(BIND_SLEEP_S, "post-bind settle"),
    ]


def _flash_step(role: str, port: str, images_dir) -> dict:
    binp = Path(images_dir) / IMAGE_FOR_ROLE[role][0]
    step = _cmd(["sudo", "esptool.py", "--chip", "esp32", "--port", port,
                 "--baud", "115200", "--after", "no-reset", "write-flash",
                 "0x0", binp],
                label=f"flash {role} merged image (prebuilt, as-is at 0x0)",
                timeout=ESPTOOL_TIMEOUT_S)
    step["ladder"] = True
    return step


def _pcscd_restart_steps() -> list:
    return [
        _cmd(["sudo", "rm", "-f", PCSCD_COMM], label="clear stale pcscd comm socket"),
        _cmd(["sudo", "systemctl", "restart", "pcscd.socket", "pcscd.service"],
             label="restart pcscd"),
        _sleep(PCSCD_SETTLE_S, "pcscd settle"),
    ]


def _probe_step() -> dict:
    return {"kind": "readers_probe", "label": "pcscd readers probe",
            "on_probe_failed": [
                _cmd(["sudo", "rm", "-f", PCSCD_COMM],
                     label="clear stale pcscd comm socket (retry)"),
                _cmd(["sudo", "systemctl", "restart", "pcscd.service"],
                     label="restart pcscd (once-retry)"),
                _sleep(PCSCD_RETRY_SETTLE_S, "pcscd retry settle"),
                {"kind": "readers_probe", "label": "pcscd readers probe (retry)"},
            ]}


def _verify_step(role: str) -> dict:
    expect = ({"includes": ["GemPCTwin serial", "ACR1252"], "excludes": []}
              if role == "ccid" else
              {"includes": ["ACR1252"], "excludes": ["GemPC"]})
    return {"kind": "verify", "label": f"strict verify {role} readers",
            "expect": expect, "ladder": True}


def dry_graph(role: str, *, port: str = STICK_PORT, staged_conf=STAGED_CONF,
              images_dir=IMAGES_DIR, conf_dir=CONF_DIR) -> list:
    """Pure command-sequence for a role — no IO, no hardware. This is the
    SINGLE source of truth switch_to() executes (the executor walks this
    exact plan), so graph and runtime can never drift."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {role!r}")
    conf_dir = Path(conf_dir)
    if role == "ccid":
        plan = [
            _cmd(["sudo", "systemctl", "stop", "bolty-console"],
                 label="stop bolty-console (frees the port)"),
            _cmd(["sudo", "cp", str(staged_conf), str(conf_dir / CONF_ACTIVE)],
                 label=f"install staged reader conf -> {CONF_ACTIVE} (PRESENT)"),
            _cmd(["sudo", "systemctl", "stop", "pcscd.socket", "pcscd.service"],
                 label="stop pcscd before flash"),
        ]
    else:
        plan = [
            _cmd(["sudo", "systemctl", "stop", "bolty-console"],
                 label="stop any port holders", tolerant=True),
            _cmd(["sudo", "rm", "-f", str(conf_dir / CONF_ACTIVE),
                  str(conf_dir / CONF_DISABLED)],
                 label=f"remove reader conf ({CONF_ACTIVE} ABSENT — never "
                       f"`.disabled`; task-1 pcscd-parse finding)", tolerant=True),
            _cmd(["sudo", "systemctl", "stop", "pcscd.socket", "pcscd.service"],
                 label="stop pcscd before flash"),
        ]
    plan.append(_flash_step(role, port, images_dir))
    plan.append({"kind": "rts_pulse", "port": port,
                 "label": "rts_pulse_reset (DTR-first, switch_role.sh:31-37)"})
    plan.extend(_rescan_steps())
    plan.extend(_pcscd_restart_steps())
    plan.append(_probe_step())
    plan.append(_verify_step(role))
    if role == "bolty":
        plan.append(_cmd(["sudo", "systemctl", "start", "bolty-console"],
                         label="start bolty-console daemon"))
        plan.append(_sleep(CONSOLE_START_S, "console start settle"))
        plan.append({"kind": "ping_verify", "label": "bolty-console PING alive",
                     "ladder": True})
    return plan


# ------------------------------------------------- persistence (todo 5) ----

class _TimelineStore:
    """Standalone incremental persistence — write-temp+fsync+rename after
    EVERY row (todo-5 protocol), so a dead gate still leaves the full
    timeline on disk."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rows: list = []

    def append(self, row: dict) -> None:
        self.rows.append(row)
        tmp = self.path.with_name(self.path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.rows, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


class Recorder:
    """Timeline rows: always collected in memory; persisted via the ctx
    (orchestrator ResultsStore — atomic per row) and/or a standalone
    _TimelineStore; anomalies escalate through ctx.anomaly when present."""

    def __init__(self, ctx=None, results_dir=None, clock=None):
        self.ctx = ctx
        self.clock = clock or time
        self.rows: list = []
        self.store = (_TimelineStore(Path(results_dir) / "role_switch_timeline.json")
                      if results_dir and ctx is None else None)

    def row(self, *, kind: str, label: str, status: str = "OK", **fields) -> dict:
        row = {"ts": _iso(self.clock.time()), "step": len(self.rows) + 1,
               "kind": kind, "label": label, "status": status}
        row.update(fields)
        self.rows.append(row)
        if self.store is not None:
            self.store.append(row)
        if self.ctx is not None:  # duck-typed PhaseContext (todo 5)
            self.ctx.row(type="role_switch", **{k: v for k, v in row.items()
                                                if k != "ts"})
        return row

    def anomaly(self, kind: str, **fields) -> dict:
        if self.ctx is not None:
            return self.ctx.anomaly(kind, **fields)
        return self.row(kind=kind, label=kind, status="ANOMALY",
                        level="anomaly", **fields)


@dataclass
class SwitchResult:
    """GateResult-compatible (.ok/.detail) plus gate bookkeeping."""
    ok: bool
    detail: str = ""
    role: str = ""
    hardware_touched: bool = False
    rows: list = field(default_factory=list)


# --------------------------------------------------------------- engine ----

class RoleSwitcher:
    def __init__(self, *, deps: Optional[Deps] = None, ctx=None,
                 images_dir=IMAGES_DIR, staged_conf=None, conf_dir=CONF_DIR,
                 repo_reader_conf=None, port: str = STICK_PORT,
                 results_dir=None, clock=None):
        self.deps = deps or Deps()
        self.ctx = ctx
        self.images_dir = Path(images_dir)
        self.staged_conf = (Path(staged_conf) if staged_conf is not None
                            else self.images_dir / "esp32-ccid.conf")
        self.conf_dir = Path(conf_dir)
        self.repo_reader_conf = (Path(repo_reader_conf) if repo_reader_conf
                                 is not None else REPO_READER_CONF)
        self.port = port
        self.recorder = Recorder(ctx=ctx, results_dir=results_dir, clock=clock)
        self._fail_why = ""

    # -- images ------------------------------------------------------------
    def verify_images(self) -> dict:
        manifest_path = self.images_dir / MANIFEST_NAME
        if not manifest_path.exists():
            raise ImageVerificationError(f"MANIFEST missing: {manifest_path}")
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, ValueError) as e:
            raise ImageVerificationError(f"MANIFEST unreadable: {e}") from e
        digests, problems = {}, []
        for role, (fname, key) in IMAGE_FOR_ROLE.items():  # BOTH roles: the
            # fallback restore must stay possible too
            p = self.images_dir / fname
            if not p.exists():
                problems.append(f"{fname} missing")
                continue
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            digests[role] = h
            expected = manifest.get(key)
            if expected != h:
                problems.append(f"{fname} sha256 {h} != manifest {expected}")
        if problems:
            raise ImageVerificationError("; ".join(problems))
        self.recorder.row(kind="image_verify", label="prebuilt image sha256 verified",
                          **digests)
        return digests

    # -- staging -----------------------------------------------------------
    def ensure_staged(self) -> list:
        """Move any /etc/reader.conf.d/esp32-ccid[.disabled] to the staging
        path (repo reader.conf as source of last resort) and verify the
        pcscd-probe elimination: NO esp32-ccid* file may remain."""
        for name in (CONF_ACTIVE, CONF_DISABLED):
            conf = self.conf_dir / name
            if not conf.exists():
                continue
            step = _cmd(["sudo", "mv", str(conf), str(self.staged_conf)],
                        label=f"stage {name} -> {self.staged_conf.name}")
            res = self._run(step)
            if res.rc != 0:
                self.recorder.row(kind="stage", label=step["label"], status="FAIL",
                                  rc=res.rc)
                raise StagingError("pcscd-probe elimination failed: "
                                   f"{conf} still present (mv rc={res.rc})")
        if not self.staged_conf.exists():
            if not self.repo_reader_conf.exists():
                raise StagingError(f"no staged conf and repo reader.conf missing: "
                                   f"{self.repo_reader_conf}")
            self.staged_conf.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repo_reader_conf, self.staged_conf)
            self.recorder.row(kind="stage", label="staged conf copied from repo",
                              src=str(self.repo_reader_conf),
                              dst=str(self.staged_conf))
        leftover = [n for n in (CONF_ACTIVE, CONF_DISABLED)
                    if (self.conf_dir / n).exists()]
        if leftover:
            raise StagingError("pcscd-probe elimination failed: "
                               f"{leftover} survive in {self.conf_dir}")
        return self.recorder.rows

    # -- step execution ----------------------------------------------------
    def _run(self, step) -> ProcResult:
        res = self.deps.runner(step["argv"], input=step.get("input"),
                               timeout=step.get("timeout"))
        status = "OK" if res.rc == 0 else ("WARN" if step.get("tolerant") else "FAIL")
        self.recorder.row(kind="cmd", label=step["label"], status=status,
                          argv=step["argv"], rc=res.rc,
                          stdout=res.stdout[-400:], stderr=res.stderr[-400:])
        return res

    def _try(self, step) -> bool:
        """One attempt of a ladder-protected step (cmd/verify/ping_verify)."""
        kind = step["kind"]
        if kind == "cmd":
            return self._run(step).rc == 0
        if kind == "verify":
            try:
                names = list(self.deps.readers())
            except Exception as e:  # pcscd down mid-probe is a probe failure
                self._fail_why = f"readers() error: {e!r}"
                self.recorder.row(kind="verify", label=step["label"], status="FAIL",
                                  error=repr(e))
                return False
            ok, self._fail_why = _check_expect(step["expect"], names)
            self.recorder.row(kind="verify", label=step["label"],
                              status="OK" if ok else "FAIL", why=self._fail_why)
            return ok
        if kind == "ping_verify":
            ok, out = self.deps.ping()
            self._fail_why = "" if ok else f"PING not alive: {out[-200:]}"
            self.recorder.row(kind="ping_verify", label=step["label"],
                              status="OK" if ok else "FAIL", output=out[-200:])
            return ok
        raise ValueError(f"unsupported ladder step kind {kind!r}")

    def _with_ladder(self, step) -> bool:
        """Wedge ladder: usb_rescan once -> USBDEVFS_RESET once -> give up."""
        if self._try(step):
            return True
        self.recorder.row(kind="wedge_ladder", label="rung 1: usb_rescan retry")
        for s in _rescan_steps():
            self._exec_step(s)
        if self._try(step):
            return True
        try:
            bus = self.deps.usb_bus_path()
        except Exception as e:
            self._fail_why = f"usb bus path resolution failed: {e!r}"
            self.recorder.row(kind="wedge_ladder", label="rung 2: bus path",
                              status="FAIL", error=repr(e))
            return False
        try:
            self.deps.usb_reset(bus)
        except Exception as e:
            self._fail_why = f"USBDEVFS_RESET failed on {bus}: {e!r}"
            self.recorder.row(kind="wedge_ladder", label="rung 2: USBDEVFS_RESET",
                              status="FAIL", bus=bus, error=repr(e))
            return False
        self.recorder.row(kind="wedge_ladder", label="rung 2: USBDEVFS_RESET",
                          bus=bus)
        return self._try(step)

    def _exec_step(self, step) -> bool:
        kind = step["kind"]
        if kind == "cmd":
            if step.get("ladder"):
                return self._with_ladder(step)
            res = self._run(step)
            return res.rc == 0 or step.get("tolerant", False)
        if kind == "sleep":
            self.deps.sleep(step["s"])
            return True  # not persisted: pure pacing, no state change
        if kind == "rts_pulse":
            try:
                self.deps.pulse(step["port"])
            except Exception as e:
                self.recorder.row(kind="rts_pulse", label=step["label"],
                                  status="FAIL", error=repr(e))
                self._fail_why = f"rts_pulse_reset failed: {e!r}"
                return False
            self.recorder.row(kind="rts_pulse", label=step["label"])
            return True
        if kind == "readers_probe":
            try:
                names = list(self.deps.readers())
            except Exception as e:
                names = []
                self.recorder.row(kind="readers_probe", label=step["label"],
                                  status="WARN", error=repr(e))
            ok = bool(names)
            if ok:
                self.recorder.row(kind="readers_probe", label=step["label"],
                                  n=len(names))
            elif step.get("on_probe_failed"):
                self.recorder.row(kind="readers_probe", label=step["label"],
                                  status="WARN", why="empty — once-retry")
                for sub in step["on_probe_failed"]:
                    self._exec_step(sub)
            return True  # the strict verify step decides pass/fail
        if kind in ("verify", "ping_verify"):
            return self._with_ladder(step)
        raise ValueError(f"unknown step kind {kind!r}")

    # -- the switch ----------------------------------------------------------
    def switch_to(self, role: str) -> SwitchResult:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, got {role!r}")
        self.recorder.row(kind="switch_begin", label=f"switch_to({role})", role=role)
        try:
            self.verify_images()
        except ImageVerificationError as e:
            self.recorder.row(kind="image_verify", status="FAIL",
                              label="prebuilt image sha256 verified", error=str(e))
            return SwitchResult(ok=False, role=role, hardware_touched=False,
                                detail=f"image sha256 verification aborted: {e}",
                                rows=self.recorder.rows)
        try:
            self.ensure_staged()
        except StagingError as e:
            return SwitchResult(ok=False, role=role, hardware_touched=False,
                                detail=f"staging failed: {e}",
                                rows=self.recorder.rows)
        plan = dry_graph(role, port=self.port, staged_conf=self.staged_conf,
                         images_dir=self.images_dir, conf_dir=self.conf_dir)
        hardware_touched = False
        for step in plan:
            if step["kind"] == "cmd" and "esptool.py" in step["argv"]:
                hardware_touched = True  # from here on the device changed
            if not self._exec_step(step):
                detail = (f"step {step['label']!r} failed after wedge ladder"
                          f" ({self._fail_why})")
                self.recorder.row(kind="switch_fail", label=f"switch_to({role})",
                                  status="FAIL", detail=detail)
                return SwitchResult(ok=False, role=role,
                                    hardware_touched=hardware_touched,
                                    detail=detail, rows=self.recorder.rows)
        detail = f"{role} role active and strictly verified"
        self.recorder.row(kind="switch_ok", label=f"switch_to({role})",
                          status="PASS", detail=detail)
        return SwitchResult(ok=True, role=role, hardware_touched=hardware_touched,
                            detail=detail, rows=self.recorder.rows)


# ---------------------------------------------------- module entrypoints ----

def ensure_staged(deps: Optional[Deps] = None, ctx=None, **kw) -> list:
    return RoleSwitcher(deps=deps, ctx=ctx, **kw).ensure_staged()


def switch_to(role: str, ctx=None, deps: Optional[Deps] = None, **kw) -> SwitchResult:
    return RoleSwitcher(deps=deps, ctx=ctx, **kw).switch_to(role)


def switch_with_fallback(role: str = "ccid", ctx=None,
                         deps: Optional[Deps] = None, **kw) -> dict:
    """The orchestrator's ROLE_GATE entrypoint.

    <=2 attempts at `role`; on failure a best-effort restore-to-bolty runs
    (only if a hardware step actually executed — an image-verification
    abort leaves the device untouched and must not trigger a reflash).
    Success -> {"mode": "Mode A"}; failure -> {"mode": "Mode B", ...}.
    Every step is a timeline row (incremental persistence per todo 5).
    """
    rs = RoleSwitcher(deps=deps, ctx=ctx, **kw)
    attempts, last = 0, None
    for _ in range(2):
        attempts += 1
        last = rs.switch_to(role)
        if last.ok:
            return {"mode": "Mode A", "ok": True, "attempts": attempts,
                    "reason": "", "detail": last.detail,
                    "timeline": rs.recorder.rows}
        if not last.hardware_touched and "image sha256" in last.detail:
            break  # deterministic abort — retrying cannot help
    restore_ok = None
    if last.hardware_touched:
        rres = rs.switch_to("bolty")
        restore_ok = rres.ok
        restore_note = f"restore {'ok' if rres.ok else 'FAILED: ' + rres.detail}"
    else:
        restore_note = "restore skipped — no hardware step executed"
    reason = (f"{role} switch failed after {attempts} attempt(s) "
              f"({last.detail}); {restore_note}")
    rs.recorder.anomaly("role_gate_failed", role=role, attempts=attempts,
                        reason=reason, restore_ok=restore_ok)
    return {"mode": "Mode B", "ok": False, "attempts": attempts, "reason": reason,
            "restore_ok": restore_ok, "detail": reason,
            "timeline": rs.recorder.rows}


def role_gate(ctx=None, **kw) -> SwitchResult:
    """GateResult-shaped adapter over switch_with_fallback (overnight.py)."""
    d = switch_with_fallback("ccid", ctx=ctx, **kw)
    return SwitchResult(ok=d["ok"], role="ccid",
                        detail=f"{d['mode']}: {d['reason']}",
                        rows=d["timeline"])


def restore_gate(ctx=None, **kw) -> SwitchResult:
    return switch_to("bolty", ctx=ctx, **kw)


# ------------------------------------------------------------ selftest ----

class _STRunner:
    def __init__(self, esptool_failures: int = 0, root=None):
        self.esptool_failures = esptool_failures
        self.root = str(Path(root).resolve()) if root else None
        self.log: list[str] = []

    def __call__(self, argv, *, input=None, timeout=None):  # noqa: A002
        line = " ".join(str(a) for a in argv)
        self.log.append(line)
        if self.esptool_failures and "esptool.py" in line:
            self.esptool_failures -= 1
            return ProcResult(rc=1, stderr="scripted flash failure")
        if argv[:2] == ["sudo", "rm"] and self.root:
            for p in argv[3:]:
                if str(p).startswith(self.root):
                    Path(p).unlink(missing_ok=True)
        return ProcResult()


class _STDeps:
    def __init__(self, runner, readers, ping_ok=True):
        self.runner, self.readers_fn, self.ping_ok = runner, readers, ping_ok
        self.pulses: list[str] = []
        self.resets: list[str] = []

    def readers(self):
        return list(self.readers_fn())

    def ping(self):
        return self.ping_ok, "alive hb_age=0s OK" if self.ping_ok else "dead"

    def pulse(self, port):
        self.pulses.append(port)

    def usb_bus_path(self):
        return "/dev/bus/usb/001/099"

    def usb_reset(self, bus_path):
        self.resets.append(bus_path)

    def sleep(self, s):
        pass


def selftest() -> tuple:
    """Offline unit paths for --selftest: graph invariants, verify
    predicates, MANIFEST hashing, wedge-ladder ordering, fallback."""
    lines: list[str] = []
    state = {"ok": True}

    def check(name: str, cond) -> None:
        lines.append(f"{'PASS' if cond else 'FAIL'}: {name}")
        state["ok"] = state["ok"] and bool(cond)

    acr = ["ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 00 00"]
    ccid_readers = acr + ["GemPCTwin serial 00 00"]

    g = dry_graph("ccid")
    argvs = [" ".join(s.get("argv", [])) for s in g]
    check("ccid graph: console stop -> conf install -> pcscd stop ordering",
          argvs[0].startswith("sudo systemctl stop bolty-console")
          and argvs[1].startswith("sudo cp ") and argvs[1].endswith("/esp32-ccid")
          and argvs[2] == "sudo systemctl stop pcscd.socket pcscd.service")
    check("ccid graph: prebuilt merged image @115200 --after no-reset at 0x0",
          any("esptool.py" in a and "--baud 115200" in a
              and "--after no-reset" in a and " write-flash 0x0 " in a + " "
              for a in argvs))
    check("ccid graph: once-retry block restarts pcscd.service",
          any(s.get("on_probe_failed") and
              any(" ".join(sub.get("argv", [])) ==
                  "sudo systemctl restart pcscd.service"
                  for sub in s["on_probe_failed"]) for s in g))
    check("ccid graph: strict verify = GemPCTwin serial AND ACR1252",
          g[-1]["expect"] == {"includes": ["GemPCTwin serial", "ACR1252"],
                              "excludes": []})
    b = dry_graph("bolty")
    bargvs = [" ".join(s.get("argv", [])) for s in b]
    check("bolty graph: conf removed (ABSENT incl. legacy .disabled)",
          any(a.startswith("sudo rm -f ") and "esp32-ccid.disabled" in a
              for a in bargvs))
    check("bolty graph: staged conf never installed",
          not any("cp" in a.split() and a.endswith("esp32-ccid") for a in bargvs))
    check("bolty graph: starts console then PING verify",
          b[-3]["argv"][1:] == ["systemctl", "start", "bolty-console"]
          and b[-1]["kind"] == "ping_verify")

    check("predicate: ccid needs BOTH readers",
          ccid_readers_ok(ccid_readers) and not ccid_readers_ok(acr))
    check("predicate: bolty rejects lingering GemPC",
          bolty_readers_ok(acr) and not bolty_readers_ok(ccid_readers))

    with tempfile.TemporaryDirectory(prefix="rs-selftest-") as td:
        td = Path(td)
        imgdir = td / "images"
        imgdir.mkdir()
        blob = b"selftest-image-bytes"
        (imgdir / "esp32-ccid-merged.bin").write_bytes(blob)
        (imgdir / "bolty-merged.bin").write_bytes(blob)
        man = {"ccid_merged_sha256": hashlib.sha256(blob).hexdigest(),
               "bolty_merged_sha256": hashlib.sha256(blob).hexdigest()}
        (imgdir / MANIFEST_NAME).write_text(json.dumps(man))
        staged = imgdir / "esp32-ccid.conf"
        staged.write_text('FRIENDLYNAME "GemPCTwin serial"\n')
        conf_dir = td / "reader.conf.d"
        conf_dir.mkdir()
        paths = {"images_dir": imgdir, "staged_conf": staged, "conf_dir": conf_dir,
                 "repo_reader_conf": td / "repo.conf", "port": "/dev/selftest"}

        check("MANIFEST sha256 verification accepts intact images",
              RoleSwitcher(**paths).verify_images() is not None)
        (imgdir / "bolty-merged.bin").write_bytes(b"tampered")
        try:
            RoleSwitcher(**paths).verify_images()
            check("MANIFEST sha256 mismatch raises", False)
        except ImageVerificationError:
            check("MANIFEST sha256 mismatch raises", True)
        (imgdir / "bolty-merged.bin").write_bytes(blob)

        runner = _STRunner(esptool_failures=3)
        res = switch_to("ccid", deps=_STDeps(runner, lambda: ccid_readers),
                        **paths)
        flash_idx = [i for i, a in enumerate(runner.log) if "esptool.py" in a]
        unbind_idx = [i for i, a in enumerate(runner.log) if "unbind" in a]
        check("wedge ladder: rescan -> usbreset -> give-up, in order",
              not res.ok and len(flash_idx) == 3
              and flash_idx[0] < unbind_idx[0] < flash_idx[1] < flash_idx[2])

        deps = _STDeps(_STRunner(), lambda: acr)  # GemPCTwin never appears
        out = switch_with_fallback("ccid", deps=deps, **paths)
        n_ccid_flash = sum("esp32-ccid-merged.bin" in a for a in deps.runner.log)
        n_bolty_flash = sum("bolty-merged.bin" in a for a in deps.runner.log)
        check("fallback: Mode B after 2 attempts + best-effort restore",
              out["mode"] == "Mode B" and out["attempts"] == 2
              and out["restore_ok"] is True and n_ccid_flash == 2
              and n_bolty_flash == 1)

    return state["ok"], lines


# ------------------------------------------------------------------ CLI ----

def _print_graph(role: str) -> None:
    plan = dry_graph(role)
    for i, s in enumerate(plan, 1):
        argv_s = " ".join(shlex.quote(a) for a in s.get("argv", []))
        extra = ""
        if s["kind"] == "sleep":
            extra = f"({s['s']}s)"
        elif s["kind"] == "rts_pulse":
            extra = f"({s['port']})"
        elif s["kind"] == "verify":
            extra = f"(expect {s['expect']})"
        flags = " [wedge-ladder]" if s.get("ladder") else ""
        if s["kind"] == "readers_probe" and s.get("on_probe_failed"):
            flags += f" (+{len(s['on_probe_failed'])} once-retry steps on empty probe)"
        print(f"{i:2d}. [{s['kind']}] {s['label']}{flags}"
              + (f": {argv_s}" if argv_s else "")
              + (f"  ({extra})" if extra else ""))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Overnight mid-night role-switch gate (todo 15). "
                    "Never flashes on its own — live round-trip is todo 18.")
    ap.add_argument("--graph", choices=ROLES,
                    help="print the exact command sequence for a role")
    ap.add_argument("--selftest", action="store_true",
                    help="run offline unit paths (no hardware, no /etc)")
    args = ap.parse_args(argv)
    if args.graph:
        _print_graph(args.graph)
        return 0
    if args.selftest:
        ok, lines = selftest()
        for ln in lines:
            print(ln)
        print("SELFTEST PASS" if ok else "SELFTEST FAIL")
        return 0 if ok else 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
