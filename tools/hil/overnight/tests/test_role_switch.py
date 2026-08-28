#!/usr/bin/env python3
"""Tests for the mid-night role-switch gate (plan todo 15).

Offline TDD suite: every hardware surface is injected — the subprocess
runner is a recording simulator (privileged fs ops are applied to tmp
paths so conf-placement transitions are really observed), readers()/PING
are faked, sleeps are no-ops. Nothing here flashes, touches /etc, or
needs pyserial/pyscard.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/overnight/tests/test_role_switch.py -q
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import role_switch  # noqa: E402
from role_switch import (  # noqa: E402
    bolty_readers_ok,
    ccid_readers_ok,
    dry_graph,
    ensure_staged,
    switch_to,
    switch_with_fallback,
)

ACR_READERS = ["ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 00 00",
               "ACS ACR1252 Dual Reader [ACR1252 Dual Reader SAM] 01 00"]
CCID_READERS = ACR_READERS + ["GemPCTwin serial 00 00"]


# ---------------------------------------------------------------- helpers ----

class ProcResult:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.rc, self.stdout, self.stderr = rc, stdout, stderr


class SimRunner:
    """Records argv; simulates the privileged fs ops (mv/cp/rm) but ONLY
    for paths under `root` (the test tmp dir) — real system paths such as
    /var/run/pcscd/pcscd.comm are recorded, never touched. Other commands
    return scripted rc values (consumed in order) or 0."""

    def __init__(self, script=None, root=None):
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.root = Path(root).resolve() if root else None
        self.calls = []  # list[tuple[list[str], bytes | None]]

    def _sandboxed(self, p):
        return self.root is not None and \
            str(Path(p).resolve()).startswith(str(self.root) + os.sep)

    def __call__(self, argv, *, input=None, timeout=None):  # noqa: A002
        argv = [str(a) for a in argv]
        self.calls.append((argv, input))
        joined = " ".join(argv)
        for key, queue in self.script.items():
            if key in joined and queue:
                rc = queue.pop(0)
                return ProcResult(rc=rc, stderr=f"scripted rc={rc}")
        if argv[:2] == ["sudo", "mv"] and self._sandboxed(argv[2]) \
                and self._sandboxed(argv[3]):
            shutil.move(argv[2], argv[3])
        elif argv[:2] == ["sudo", "cp"] and self._sandboxed(argv[2]) \
                and self._sandboxed(argv[3]):
            shutil.copyfile(argv[2], argv[3])
        elif argv[:2] == ["sudo", "rm"]:
            for p in argv[3:]:
                if self._sandboxed(p):
                    Path(p).unlink(missing_ok=True)
        return ProcResult()

    def argvs(self):
        return [c[0] for c in self.calls]

    def flat(self):
        return [" ".join(a) for a in self.argvs()]

    def count(self, needle):
        return sum(1 for line in self.flat() if needle in line)

    def first_index(self, needle):
        for i, line in enumerate(self.flat()):
            if needle in line:
                return i
        return None


class SeqReaders:
    """Pops one reader-list per call; a raised item propagates."""

    def __init__(self, seq):
        self.seq, self.calls = list(seq), []

    def __call__(self):
        self.calls.append(None)
        item = self.seq.pop(0) if self.seq else ACR_READERS
        if isinstance(item, Exception):
            raise item
        return list(item)


class Deps:
    def __init__(self, runner, readers, ping=(True, "alive hb_age=0s OK")):
        self.runner = runner
        self.readers = readers
        self.ping_fn = ping
        self.pulse_ports = []
        self.resets = []
        self.bus_paths = []

    # Deps protocol
    def ping(self):
        return self.ping_fn

    def pulse(self, port):
        self.pulse_ports.append(port)

    def usb_bus_path(self):
        self.bus_paths.append("/dev/bus/usb/001/035")
        return "/dev/bus/usb/001/035"

    def usb_reset(self, bus_path):
        self.resets.append(bus_path)

    def sleep(self, s):
        pass


def make_images(tmpdir, *, tamper_ccid=False):
    """Tiny fake image set with a REAL sha256 MANIFEST (hash path is real)."""
    imgdir = tmpdir / "images"
    imgdir.mkdir(parents=True)
    blobs = {"bolty": b"bolty-merged-fake", "ccid": b"esp32-ccid-merged-fake"}
    if tamper_ccid:
        (imgdir / "esp32-ccid-merged.bin").write_bytes(b"TAMPERED")
    else:
        (imgdir / "esp32-ccid-merged.bin").write_bytes(blobs["ccid"])
    (imgdir / "bolty-merged.bin").write_bytes(blobs["bolty"])
    (imgdir / "MANIFEST.json").write_text(json.dumps({
        "bolty_merged_sha256": hashlib.sha256(blobs["bolty"]).hexdigest(),
        "ccid_merged_sha256": hashlib.sha256(blobs["ccid"]).hexdigest(),
    }))
    staged = imgdir / "esp32-ccid.conf"
    staged.write_text('FRIENDLYNAME "GemPCTwin serial"\nDEVICENAME /dev/x\n')
    return imgdir, staged


def rig(tmp_path, *, readers, script=None, ping=(True, "alive hb_age=0s OK"),
        tamper_ccid=False, pre_existing_conf=None):
    """Build (deps, paths) with everything pointed at tmp dirs."""
    imgdir, staged = make_images(tmp_path, tamper_ccid=tamper_ccid)
    conf_dir = tmp_path / "reader.conf.d"
    conf_dir.mkdir()
    if pre_existing_conf:
        (conf_dir / pre_existing_conf).write_text("stale conf\n")
    repo_conf = tmp_path / "repo-reader.conf"
    repo_conf.write_text('FRIENDLYNAME "GemPCTwin serial" (repo)\n')
    runner = SimRunner(script, root=tmp_path)
    deps = Deps(runner, readers, ping)
    paths = {"images_dir": imgdir, "staged_conf": staged, "conf_dir": conf_dir,
             "repo_reader_conf": repo_conf,
             "port": "/dev/serial/by-id/usb-TEST-port0"}
    return deps, runner, paths


# ------------------------------------------------------------ graph tests ----

def test_graph_ccid_exact_sequence():
    port = "/dev/serial/by-id/usb-X-port0"
    staged = "/staged/esp32-ccid.conf"
    img = "/img/esp32-ccid-merged.bin"
    plan = dry_graph("ccid", port=port, staged_conf=staged,
                     images_dir="/img", conf_dir="/etc/reader.conf.d")
    seq = [(s["kind"], tuple(s.get("argv", ()))) for s in plan]
    assert seq == [
        ("cmd", ("sudo", "systemctl", "stop", "bolty-console")),
        ("cmd", ("sudo", "cp", staged, "/etc/reader.conf.d/esp32-ccid")),
        ("cmd", ("sudo", "systemctl", "stop", "pcscd.socket", "pcscd.service")),
        ("cmd", ("sudo", "esptool.py", "--chip", "esp32", "--port", port,
                 "--baud", "115200", "--after", "no-reset", "write-flash",
                 "0x0", img)),
        ("rts_pulse", ()),
        ("cmd", ("sudo", "tee", "/sys/bus/usb/drivers/usb/unbind")),
        ("sleep", ()),
        ("cmd", ("sudo", "tee", "/sys/bus/usb/drivers/usb/bind")),
        ("sleep", ()),
        ("cmd", ("sudo", "rm", "-f", "/var/run/pcscd/pcscd.comm")),
        ("cmd", ("sudo", "systemctl", "restart", "pcscd.socket", "pcscd.service")),
        ("sleep", ()),
        ("readers_probe", ()),
        ("verify", ()),
    ]
    # placement + semantics
    assert seq[1][1][3] == "/etc/reader.conf.d/esp32-ccid"  # ACTIVE name, not .disabled
    assert plan[3]["ladder"] is True and plan[3]["timeout"] == 900
    unbind, bind = plan[5], plan[7]
    assert unbind["input"] == b"1-1" and bind["input"] == b"1-1"
    assert plan[6]["s"] == 4.0 and plan[8]["s"] == 6.0
    assert plan[11]["s"] == 10.0
    # once-retry block (switch_role.sh:60-66 pattern)
    probe = plan[12]
    retry = probe["on_probe_failed"]
    assert [(s["kind"], tuple(s.get("argv", ()))) for s in retry] == [
        ("cmd", ("sudo", "rm", "-f", "/var/run/pcscd/pcscd.comm")),
        ("cmd", ("sudo", "systemctl", "restart", "pcscd.service")),
        ("sleep", ()),
        ("readers_probe", ()),
    ]
    assert retry[2]["s"] == 8.0
    assert plan[13]["ladder"] is True
    assert plan[13]["expect"] == {"includes": ["GemPCTwin serial", "ACR1252"],
                                  "excludes": []}


def test_graph_bolty_exact_sequence():
    port = "/dev/serial/by-id/usb-X-port0"
    plan = dry_graph("bolty", port=port, staged_conf="/staged/esp32-ccid.conf",
                     images_dir="/img", conf_dir="/etc/reader.conf.d")
    seq = [(s["kind"], tuple(s.get("argv", ()))) for s in plan]
    assert seq == [
        ("cmd", ("sudo", "systemctl", "stop", "bolty-console")),
        ("cmd", ("sudo", "rm", "-f", "/etc/reader.conf.d/esp32-ccid",
                 "/etc/reader.conf.d/esp32-ccid.disabled")),
        ("cmd", ("sudo", "systemctl", "stop", "pcscd.socket", "pcscd.service")),
        ("cmd", ("sudo", "esptool.py", "--chip", "esp32", "--port", port,
                 "--baud", "115200", "--after", "no-reset", "write-flash",
                 "0x0", "/img/bolty-merged.bin")),
        ("rts_pulse", ()),
        ("cmd", ("sudo", "tee", "/sys/bus/usb/drivers/usb/unbind")),
        ("sleep", ()),
        ("cmd", ("sudo", "tee", "/sys/bus/usb/drivers/usb/bind")),
        ("sleep", ()),
        ("cmd", ("sudo", "rm", "-f", "/var/run/pcscd/pcscd.comm")),
        ("cmd", ("sudo", "systemctl", "restart", "pcscd.socket", "pcscd.service")),
        ("sleep", ()),
        ("readers_probe", ()),
        ("verify", ()),
        ("cmd", ("sudo", "systemctl", "start", "bolty-console")),
        ("sleep", ()),
        ("ping_verify", ()),
    ]
    # conf is ABSENT (both names removed), never a cp / .disabled write
    flat = json.dumps(plan, default=repr)
    assert "/staged/esp32-ccid.conf" not in flat  # staged copy NOT installed
    assert plan[0]["tolerant"] is True
    assert plan[1]["tolerant"] is True
    assert plan[13]["expect"] == {"includes": ["ACR1252"], "excludes": ["GemPC"]}
    assert plan[13]["ladder"] is True and plan[16]["ladder"] is True
    assert plan[15]["s"] == 6.0  # console start settle (switch_role.sh:88)


def test_graph_is_pure_and_serializable():
    for role in ("ccid", "bolty"):
        plan = dry_graph(role)  # default paths, no IO
        # JSON-clean apart from the deliberate bytes tee payloads
        assert plan and json.dumps(plan, default=repr)


# ------------------------------------------------------- ensure_staged ----

def test_ensure_staged_moves_disabled_and_eliminates(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([ACR_READERS]),
                              pre_existing_conf="esp32-ccid.disabled")
    paths["staged_conf"].unlink()  # force the move to create it
    rows = ensure_staged(deps=deps, **paths)
    assert not list(paths["conf_dir"].glob("esp32-ccid*"))  # elimination
    assert paths["staged_conf"].read_text() == "stale conf\n"
    assert any(a[:2] == ["sudo", "mv"] for a in runner.argvs())
    assert all(r["status"] == "OK" for r in rows)


def test_ensure_staged_falls_back_to_repo_conf(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([ACR_READERS]))
    paths["staged_conf"].unlink()
    ensure_staged(deps=deps, **paths)
    assert paths["staged_conf"].read_text() == 'FRIENDLYNAME "GemPCTwin serial" (repo)\n'
    assert not list(paths["conf_dir"].glob("esp32-ccid*"))


def test_ensure_staged_noop_when_clean(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([ACR_READERS]))
    before = paths["staged_conf"].read_text()
    ensure_staged(deps=deps, **paths)
    assert runner.calls == []  # nothing to do
    assert paths["staged_conf"].read_text() == before


def test_ensure_staged_raises_when_conf_survives(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([ACR_READERS]),
                              pre_existing_conf="esp32-ccid",
                              script={"mv": [1]})
    with pytest.raises(role_switch.StagingError, match="elimination"):
        ensure_staged(deps=deps, **paths)


# ------------------------------------------------- manifest verification ----

def test_manifest_hash_mismatch_aborts_before_any_flash(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([CCID_READERS]),
                              tamper_ccid=True)
    res = switch_to("ccid", deps=deps, **paths)
    assert not res.ok and "sha256" in res.detail and not res.hardware_touched
    assert runner.count("esptool.py") == 0  # aborted BEFORE any flash
    # fallback: deterministic abort -> single attempt, no restore reflash
    out = switch_with_fallback("ccid", deps=deps, **paths)
    assert out["mode"] == "Mode B" and out["attempts"] == 1
    assert runner.count("esptool.py") == 0  # restore skipped (device untouched)
    assert any("sha256" in json.dumps(r) for r in out["timeline"])


def test_switch_ccid_success_orders_and_placement(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([CCID_READERS] * 10))
    res = switch_to("ccid", deps=deps, **paths)
    assert res.ok, res.detail
    i = runner.first_index  # containment search over full argv joins
    assert i("stop bolty-console") < \
        i(f"sudo cp {paths['staged_conf']} {paths['conf_dir']}/esp32-ccid") < \
        i("stop pcscd.socket pcscd.service") < \
        i("sudo esptool.py") < \
        i("sudo tee /sys/bus/usb/drivers/usb/unbind") < \
        i("restart pcscd.socket pcscd.service")
    assert (paths["conf_dir"] / "esp32-ccid").exists()  # conf now PRESENT
    assert deps.pulse_ports == [paths["port"]]  # rts_pulse after flash
    assert runner.count("restart pcscd.socket pcscd.service") == 1  # mainline
    assert ["sudo", "systemctl", "restart", "pcscd.service"] \
        not in runner.argvs()  # no once-retry needed


def test_switch_bolty_success_and_conf_absent(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([ACR_READERS] * 10),
                              pre_existing_conf="esp32-ccid")
    res = switch_to("bolty", deps=deps, **paths)
    assert res.ok, res.detail
    assert not (paths["conf_dir"] / "esp32-ccid").exists()  # ABSENT, not .disabled
    assert not list(paths["conf_dir"].glob("esp32-ccid*"))
    assert any("start bolty-console" in a for a in runner.flat())
    assert deps.ping_fn[0] is True  # PING alive was asserted


def test_bolty_verify_rejects_lingering_gempc(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([CCID_READERS] * 10))
    res = switch_to("bolty", deps=deps, **paths)
    assert not res.ok  # strict: a lingering GemPC reader FAILS bolty mode
    assert "GemPC" in res.detail
    assert ccid_readers_ok(CCID_READERS) and not ccid_readers_ok(ACR_READERS)
    assert bolty_readers_ok(ACR_READERS) and not bolty_readers_ok(CCID_READERS)


# --------------------------------------------------------- wedge ladder ----

def test_wedge_ladder_order_then_gives_up(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([CCID_READERS] * 10),
                              script={"esptool.py": [1, 1, 1]})
    res = switch_to("ccid", deps=deps, **paths)
    assert not res.ok and res.hardware_touched
    idx = [i for i, line in enumerate(runner.flat()) if "esptool.py" in line]
    unbind = [i for i, line in enumerate(runner.flat()) if "unbind" in line]
    assert len(idx) == 3  # initial + rescan retry + reset retry
    assert idx[0] < unbind[0] < idx[1] < idx[2]  # rescan BETWEEN flash attempts
    assert len(deps.resets) == 1 and deps.resets[0] == "/dev/bus/usb/001/035"
    assert deps.bus_paths == ["/dev/bus/usb/001/035"]  # resolved once, after rescan
    assert "wedge ladder" in res.detail  # gave up that direction


def test_wedge_ladder_rescues_after_rescan(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([CCID_READERS] * 10),
                              script={"esptool.py": [1, 0]})
    res = switch_to("ccid", deps=deps, **paths)
    assert res.ok, res.detail
    assert deps.resets == []  # USBDEVFS_RESET never needed
    assert runner.count("sudo tee /sys/bus/usb/drivers/usb/unbind") == 2  # ladder + mainline


# ------------------------------------------------------------- fallback ----

def test_fallback_mode_b_after_two_attempts_with_restore(tmp_path):
    deps, runner, paths = rig(tmp_path, readers=SeqReaders([ACR_READERS] * 40))
    out = switch_with_fallback("ccid", deps=deps, **paths)
    assert out["mode"] == "Mode B" and out["ok"] is False
    assert out["attempts"] == 2 and out["restore_ok"] is True
    assert out["reason"] and out["timeline"]
    assert runner.count("esp32-ccid-merged.bin") == 2  # two ccid attempts
    assert runner.count("bolty-merged.bin") == 1       # best-effort restore
    assert any("start bolty-console" in a for a in runner.flat())


def test_fallback_mode_a_on_second_attempt(tmp_path):
    seq = [ACR_READERS] * 5 + [CCID_READERS] * 10  # attempt 1 verify fails, then ok
    deps, runner, paths = rig(tmp_path, readers=SeqReaders(seq))
    out = switch_with_fallback("ccid", deps=deps, **paths)
    assert out["mode"] == "Mode A" and out["ok"] is True and out["attempts"] == 2
    assert runner.count("bolty-merged.bin") == 0  # no restore on success


def test_pcscd_once_retry_triggers_only_on_failed_probe(tmp_path):
    seq = [[], CCID_READERS, CCID_READERS]  # probe empty -> retry -> verify
    deps, runner, paths = rig(tmp_path, readers=SeqReaders(seq))
    res = switch_to("ccid", deps=deps, **paths)
    assert res.ok, res.detail
    assert "sudo systemctl restart pcscd.service" in runner.flat()  # retry ran

    seq2 = [CCID_READERS] * 5
    deps2, runner2, paths2 = rig(tmp_path / "b", readers=SeqReaders(seq2))
    res2 = switch_to("ccid", deps=deps2, **paths2)
    assert res2.ok, res2.detail
    assert "sudo systemctl restart pcscd.service" not in runner2.flat()


# ------------------------------------------------------------------ CLI ----

def test_cli_graph_and_selftest():
    here = Path(role_switch.__file__)
    g = subprocess.run([sys.executable, str(here), "--graph", "ccid"],
                       capture_output=True, text=True, timeout=60)
    assert g.returncode == 0 and "write-flash" in g.stdout
    assert "/etc/reader.conf.d/esp32-ccid" in g.stdout
    b = subprocess.run([sys.executable, str(here), "--graph", "bolty"],
                       capture_output=True, text=True, timeout=60)
    assert b.returncode == 0 and "bolty-merged.bin" in b.stdout
    st = subprocess.run([sys.executable, str(here), "--selftest"],
                        capture_output=True, text=True, timeout=120)
    assert st.returncode == 0, st.stdout + st.stderr
    assert "SELFTEST PASS" in st.stdout
