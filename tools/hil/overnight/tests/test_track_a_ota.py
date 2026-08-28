#!/usr/bin/env python3
"""Tests for the overnight Track A OTA-negative suite (plan todo 9).

Pure-logic TDD suite: local OTA server handler behaviors (normal /
truncated-bytes math / 404 / one-shot / bind guard), wrong-signature
factory format validation + valid-signature non-reuse, rejection-marker
parser incl. NOT-committing evidence, capability-gate skip logic, and
CaseRunner timeout + max-2-attempt enforcement.

No device, no network beyond loopback (the OTA server binds 127.0.0.1).
ota-sign.py IS invoked for real (local subprocess, throwaway keys under
a tmp dir) because signature generation is the case-(a) attack surface.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/overnight/tests/test_track_a_ota.py -q
"""

import http.client
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import track_a_ota  # noqa: E402
from track_a_ota import (  # noqa: E402
    CASE_TIMEOUT_S,
    MAX_ATTEMPTS,
    OtaCapabilityError,
    LocalOtaServer,
    SignatureFactory,
    parse_rejection_evidence,
)

REPO = Path(__file__).resolve().parents[4]
FW_IMAGE = Path.home() / "fw-backup" / "bolty-esp32-ota-image-20260827.bin"
VALID_SIG_HEX = (Path.home() / "fw-backup" / "ota_sig.hex").read_text().strip()


# ---------------------------------------------------------------- helpers ----


class FakeClock:
    """Monotonic-ish clock the tests fully control."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def advance(self, s):
        self.now += s


class FakeConsole:
    """Scripted stand-in for the bolty-console unix-socket client."""

    def __init__(self, help_has_ota=True, ota_response=None, ver="ver 1.2.3",
                 ping="alive hb_age=3s", stall_s=0.0):
        self.help_text = ("cmd: burn ... OTA: ota <url> ..." if help_has_ota
                          else "cmd: burn wipe status")
        self.ota_response = ota_response if ota_response is not None else [
            "I (123) ota: starting signed ota update from http://x/fw.bin",
            "I (124) ota: ota progress: 1216 KB",
            "E (125) ota: [FAIL] firmware signature verification FAILED",
        ]
        self.ver_text = ver
        self.ping_text = ping
        self.stall_s = stall_s
        self.ota_sends = []

    def cmd(self, line, timeout=30.0):
        if self.stall_s:
            time.sleep(self.stall_s)
        if line == "help":
            return self.help_text.splitlines()
        if line == "ver":
            return self.ver_text.splitlines()
        if line == "PING":
            return self.ping_text.splitlines()
        if line.startswith("ota "):
            self.ota_sends.append(line)
            return list(self.ota_response)
        raise AssertionError(f"unexpected console command: {line!r}")

    def raw(self, secs):
        return []


class RecordingCtx:
    """Duck-typed PhaseContext (overnight.py) capturing rows/skips/anomalies."""

    def __init__(self, dry_run=False):
        self.rows = []
        self.skips = []
        self.anomalies = []
        self.dry_run = dry_run
        self.name = "track_a_ota_test"

    def running(self):
        return True

    def sleep(self, s):
        pass

    def row(self, **fields):
        self.rows.append(fields)
        return fields

    def skip(self, reason, **fields):
        rec = {"type": "SKIP", "status": "SKIP", "reason": reason, **fields}
        self.skips.append(rec)
        return rec

    def anomaly(self, kind, **fields):
        rec = {"kind": kind, **fields}
        self.anomalies.append(rec)
        return rec

    def event(self, kind, **fields):
        return {"kind": kind, **fields}


# ---------------------------------------------------------------- server ----


class TestLocalOtaServer:
    def test_normal_serves_full_image_bytes(self, tmp_path):
        image = tmp_path / "fw.bin"
        image.write_bytes(b"A" * 1000)
        srv = LocalOtaServer(host="127.0.0.1", image_path=image)
        srv.arm(path="/fw.bin", mode="normal")
        srv.start()
        try:
            with urllib.request.urlopen(srv.url("/fw.bin"), timeout=5) as r:
                body = r.read()
            assert r.status == 200
            assert body == b"A" * 1000
            assert r.headers["Content-Length"] == "1000"
        finally:
            srv.stop()

    def test_truncated_declares_full_length_closes_after_40pct(self, tmp_path):
        n = 1000
        image = tmp_path / "fw.bin"
        image.write_bytes(b"B" * n)
        srv = LocalOtaServer(host="127.0.0.1", image_path=image)
        srv.arm(path="/t.bin", mode="truncated")
        srv.start()
        try:
            received = 0
            try:
                with urllib.request.urlopen(srv.url("/t.bin"), timeout=5) as r:
                    received = len(r.read())
            except http.client.IncompleteRead as e:
                received = e.partial and len(e.partial) or 0
            except (ConnectionResetError, http.client.HTTPException):
                pass  # connection torn down mid-stream: also acceptable
            assert received < n, "server must NOT deliver the full image"
            assert srv.served_bytes == n * 40 // 100
            assert srv.declared_length == n
        finally:
            srv.stop()

    def test_missing_path_returns_404(self, tmp_path):
        image = tmp_path / "fw.bin"
        image.write_bytes(b"C" * 10)
        srv = LocalOtaServer(host="127.0.0.1", image_path=image)
        srv.arm(path="/fw.bin", mode="normal")
        srv.start()
        try:
            with pytest.raises(urllib.error.HTTPError) as ei:
                urllib.request.urlopen(srv.url("/nope.bin"), timeout=5)
            assert ei.value.code == 404
        finally:
            srv.stop()

    def test_one_shot_state_second_fetch_not_served(self, tmp_path):
        image = tmp_path / "fw.bin"
        image.write_bytes(b"D" * 100)
        srv = LocalOtaServer(host="127.0.0.1", image_path=image)
        srv.arm(path="/fw.bin", mode="normal")
        srv.start()
        try:
            with urllib.request.urlopen(srv.url("/fw.bin"), timeout=5) as r:
                first = r.read()
            assert first == b"D" * 100
            # one-shot: the armed case was consumed; re-fetch must NOT serve
            with pytest.raises(urllib.error.HTTPError) as ei:
                urllib.request.urlopen(srv.url("/fw.bin"), timeout=5)
            assert ei.value.code == 404
            assert len([q for q in srv.requests if q["path"] == "/fw.bin"]) == 2
            assert srv.served_count == 1
        finally:
            srv.stop()

    def test_bind_guard_rejects_wildcard_and_foreign(self, tmp_path):
        image = tmp_path / "fw.bin"
        image.write_bytes(b"E")
        for bad in ("0.0.0.0", "192.0.2.55", "example.com"):
            with pytest.raises(ValueError):
                LocalOtaServer(host=bad, image_path=image)

    def test_lan_ip_resolution_yields_private_addr(self):
        ip = track_a_ota.resolve_lan_ip()
        assert ip is None or ip.startswith("192.168.") or ip.startswith("10.") \
            or ip.startswith("172.")


# --------------------------------------------------------- signature factory ----


class TestSignatureFactory:
    def test_throwaway_signature_is_valid_128_hex_and_not_the_valid_sig(self, tmp_path):
        fw = tmp_path / "fw.bin"
        fw.write_bytes(b"\x00" * 2048)
        factory = SignatureFactory(repo_root=REPO, workdir=tmp_path / "ota_tmp")
        sig = factory.wrong_signature(fw)
        assert len(sig) == 128
        int(sig, 16)  # must be hex
        assert sig.lower() == sig
        assert sig != VALID_SIG_HEX  # NEVER reuse the VALID signature
        factory.wipe()
        assert not (tmp_path / "ota_tmp").exists()

    def test_malformed_sign_output_rejected(self, tmp_path):
        factory = SignatureFactory(repo_root=REPO, workdir=tmp_path / "ota_tmp")
        with pytest.raises(track_a_ota.SignatureError):
            factory._extract_signature(
                "Firmware: x (2 bytes)\nSHA-256: ab\nSignature: nothex\n"
            )
        with pytest.raises(track_a_ota.SignatureError):
            factory._extract_signature("totally unrelated output")

    def test_valid_sig_file_is_never_a_factory_output(self, tmp_path):
        # guard: even if ota_sig.hex path is passed in, factory refuses to
        # return it (defense against future misuse)
        factory = SignatureFactory(repo_root=REPO, workdir=tmp_path / "ota_tmp")
        with pytest.raises(track_a_ota.SignatureError):
            factory._extract_signature(
                f"Firmware: x (2 bytes)\nSHA-256: 00\nSignature: {VALID_SIG_HEX}\n"
            )


# ------------------------------------------------------------- marker parser ----


class TestRejectionEvidenceParser:
    def test_wrong_signature_detected(self):
        fail_line = "E (103) ota: [FAIL] firmware signature verification FAILED"
        lines, commit = parse_rejection_evidence([
            "I (100) ota: starting signed ota update from http://192.168.13.2:41001/fw.bin",
            "I (101) ota: ota progress: 1216 KB",
            "I (102) ota: ota image written: 1266864 bytes",
            fail_line,
        ])
        assert lines == [fail_line]  # raw console lines are the evidence
        assert commit == []

    def test_http_404_detected(self):
        lines, commit = parse_rejection_evidence(["E (10) ota: [FAIL] http status 404"])
        assert lines and "404" in lines[0]

    def test_truncated_read_error_detected(self):
        lines, commit = parse_rejection_evidence(
            ["E (20) ota: [FAIL] http: EspIOError(EspError(118))]"])
        assert lines

    def test_unprovisioned_is_degradation_not_rejection(self):
        lines, commit = parse_rejection_evidence(
            ["E (30) ota: [FAIL] OTA signing key not provisioned (run 'provision-ota-key')"])
        assert lines == []
        assert track_a_ota.find_unprovisioned(
            ["[FAIL] OTA signing key not provisioned (run 'provision-ota-key')"])

    def test_committing_evidence_is_flagged_never_pass(self):
        lines, commit = parse_rejection_evidence([
            "I (200) ota: ota image written: 1266864 bytes",
            "I (201) ota: ota signature VERIFIED — committing",
            "I (202) ota: [OK] rebooting",
        ])
        assert lines == []
        assert len(commit) == 2  # VERIFIED + rebooting both present

    def test_empty_evidence_is_no_evidence(self):
        lines, commit = parse_rejection_evidence([])
        assert lines == [] and commit == []


# ---------------------------------------------------------- capability gate ----


class TestCapabilityGate:
    def test_help_without_ota_skips(self):
        ctx = RecordingCtx()
        console = FakeConsole(help_has_ota=False)
        track_a_ota.capability_gate(ctx, console)
        assert len(ctx.skips) == 1
        assert "ota" in ctx.skips[0]["reason"]

    def test_help_with_ota_passes(self):
        ctx = RecordingCtx()
        track_a_ota.capability_gate(ctx, FakeConsole(help_has_ota=True))
        assert ctx.skips == []

    def test_console_error_raises_capability_error(self):
        class DeadConsole(FakeConsole):
            def cmd(self, line, timeout=30.0):
                raise OSError("console daemon gone")

        with pytest.raises(OtaCapabilityError):
            track_a_ota.capability_gate(RecordingCtx(), DeadConsole())


# -------------------------------------------------------------- case runner ----


class TestCaseRunner:
    def _runner(self, console, ctx=None, clock=None):
        return track_a_ota.CaseRunner(
            console=console, ctx=ctx or RecordingCtx(), clock=clock or FakeClock())

    def test_wrong_sig_case_passes_and_ver_identical(self):
        console = FakeConsole()
        runner = self._runner(console)
        row = runner.run_case(
            name="wrong_signature", url="http://127.0.0.1:1/fw.bin",
            sig="ab" * 64)
        assert row["status"] == "PASS"
        assert row["case"] == "wrong_signature"
        assert row["evidence"]
        assert len(console.ota_sends) == 1

    def test_ver_change_fails_the_case(self):
        console = FakeConsole()
        calls = {"n": 0}

        def ver_spy(line, timeout=30.0):
            if line == "ver":
                calls["n"] += 1
                return [f"ver 1.0.{calls['n']}"]  # changes after ota
            return FakeConsole.cmd(console, line, timeout)

        console.cmd = ver_spy
        row = self._runner(console).run_case(
            name="wrong_signature", url="http://x/fw.bin", sig="cd" * 64)
        assert row["status"] == "FAIL"
        assert "ver" in row["fail_reason"]

    def test_no_rejection_evidence_fails(self):
        console = FakeConsole(ota_response=["I (1) silence"])
        row = self._runner(console).run_case(
            name="wrong_signature", url="http://x/fw.bin", sig="ef" * 64)
        assert row["status"] == "FAIL"

    def test_unprovisioned_key_yields_skip_row(self):
        console = FakeConsole(ota_response=[
            "E (5) ota: [FAIL] OTA signing key not provisioned (run 'provision-ota-key')"])
        ctx = RecordingCtx()
        self._runner(console, ctx=ctx).run_case(
            name="wrong_signature", url="http://x/fw.bin", sig="00" * 64)
        assert ctx.skips and "otakey" in ctx.skips[0]["reason"]

    def test_committing_evidence_fails_immediately_no_retry(self):
        console = FakeConsole(ota_response=[
            "I (1) ota: ota signature VERIFIED — committing",
            "[OK] rebooting",
        ])
        row = self._runner(console).run_case(
            name="wrong_signature", url="http://x/fw.bin", sig="11" * 64)
        assert row["status"] == "FAIL"
        assert "commit" in row["fail_reason"].lower() or \
            "verified" in row["fail_reason"].lower()
        assert len(console.ota_sends) == 1  # NEVER re-send after commit evidence

    def test_transport_failure_retries_at_most_twice(self):
        class FlakyConsole(FakeConsole):
            def cmd(self, line, timeout=30.0):
                if line.startswith("ota "):
                    self.ota_sends.append(line)
                    raise TimeoutError("daemon cap hit")
                return FakeConsole.cmd(self, line, timeout)

        clock = FakeClock()
        flaky = FlakyConsole()
        assert MAX_ATTEMPTS == 2
        row = self._runner(flaky, clock=clock).run_case(
            name="wrong_signature", url="http://x/fw.bin", sig="22" * 64)
        assert row["status"] == "FAIL"
        assert len(flaky.ota_sends) == MAX_ATTEMPTS  # hard attempt cap held

    def test_case_deadline_enforced_120s(self):
        assert CASE_TIMEOUT_S == 120
        clock = FakeClock()
        console = FakeConsole(ota_response=["I (1) nothing useful"])
        runner = self._runner(console, clock=clock)
        # advance the clock past the case budget between commands
        orig_cmd = console.cmd

        def advancing_cmd(line, timeout=30.0):
            clock.advance(70)
            return orig_cmd(line, timeout)

        console.cmd = advancing_cmd
        row = runner.run_case(name="x", url="http://x/fw.bin", sig="33" * 64)
        assert row["status"] == "FAIL"
        assert "timeout" in row["fail_reason"].lower() \
            or "budget" in row["fail_reason"].lower()

    def test_ping_dead_fails_liveness(self):
        console = FakeConsole(ping="dead")  # no 'alive' in PING response
        row = self._runner(console).run_case(
            name="wrong_signature", url="http://x/fw.bin", sig="44" * 64)
        assert row["status"] == "FAIL"
        assert "alive" in row["fail_reason"]


# ---------------------------------------------------------------- register ----


class TestRegister:
    def test_register_dry_run_emits_simulated_rows_no_hardware(self, tmp_path):
        ctx = RecordingCtx(dry_run=True)
        track_a_ota.register(ctx)
        kinds = [r.get("case") for r in ctx.rows]
        assert kinds == ["wrong_signature", "truncated_download", "http_404"]
        assert all(r["status"] == "PASS" and r.get("simulated") for r in ctx.rows)

    def test_register_gates_then_runs_cases_with_real_server(self, tmp_path):
        # integration shape: fake console + real loopback server + tmp image
        image = tmp_path / "fw.bin"
        image.write_bytes(b"F" * 500)
        console = FakeConsole(help_has_ota=True)
        ctx = RecordingCtx()
        track_a_ota.register(
            ctx, console=console, image_path=image,
            sig_factory=SignatureFactory(repo_root=REPO, workdir=tmp_path / "w"))
        assert len(console.ota_sends) == 3
        assert all(r["status"] == "PASS" for r in ctx.rows), ctx.rows

    def test_register_skips_all_when_gate_fails(self):
        console = FakeConsole(help_has_ota=False)
        ctx = RecordingCtx()
        track_a_ota.register(ctx, console=console,
                             image_path=Path("/nonexistent"),
                             sig_factory=None)
        assert ctx.skips and not ctx.rows
        assert not console.ota_sends
