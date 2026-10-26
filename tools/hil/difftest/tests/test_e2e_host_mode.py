"""Unit tests for e2e.py host-aware runner plumbing (#216).

The ssh-wrap is pure host-side logic — verified here with stubbed
subprocess.run, no network, no readers.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # difftest/

import e2e  # noqa: E402


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestLocalModePassthrough:
    def test_local_run_untouched_without_host(self, monkeypatch, tmp_path):
        monkeypatch.setattr(e2e, "SSH_HOST", None)
        seen = {}

        def fake_run(cmd, cwd=None, timeout=120, **kw):
            seen["cmd"] = cmd
            return (0, "local-out")

        monkeypatch.setattr(e2e, "run", fake_run)
        rc, out, got = e2e.run_reader_cmd(["echo", "hi"], timeout=5)
        assert rc == 0 and out == "local-out"
        assert seen["cmd"] == ["echo", "hi"]
        assert got is None  # no output path requested


class TestHostModeSshWrap:
    def _install(self, monkeypatch, responses, remote_home="/home/bench"):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            if len(calls) <= len(responses):
                return responses[len(calls) - 1]
            return _FakeProc(0, remote_home + "\n")  # any $HOME probe

        monkeypatch.setattr(e2e, "SSH_HOST", "bench-host")
        monkeypatch.setattr(e2e, "_remote_home_cache", remote_home)
        monkeypatch.setattr(e2e.subprocess, "run", fake_run)
        return calls

    def test_ssh_prefix_and_cwd(self, monkeypatch):
        calls = self._install(monkeypatch, [_FakeProc(0, "ok")])
        e2e.run_reader_cmd(["python3", "-c", "print(1)"])
        argv = calls[0]
        assert argv[:6] == ["ssh", "-o", "BatchMode=yes",
                            "-o", "ConnectTimeout=10", "bench-host"]
        shell = argv[6]
        assert "cd " in shell
        # tilde form must not survive literally (shlex freezes it) — it is
        # resolved against the remote $HOME to an absolute path
        assert "/home/bench/src/bolty-rs-acr-h1/tools/hil/difftest" in shell
        assert "~" not in shell

    def test_local_paths_map_to_remote_dir(self, monkeypatch):
        calls = self._install(monkeypatch, [_FakeProc(0, "ok")])
        e2e.run_reader_cmd(["python3", str(e2e.HERE / "capture.py"), "--reader", "PICC"])
        shell = calls[0][6]
        assert str(e2e.HERE / "capture.py") not in shell
        assert "/home/bench/src/bolty-rs-acr-h1/tools/hil/difftest/capture.py" in shell

    def test_output_fetched_back_locally(self, monkeypatch, tmp_path):
        payload = json.dumps({"reader": "x", "results": []})
        calls = self._install(monkeypatch, [
            _FakeProc(0, "captured"),
            _FakeProc(0, stdout=payload.encode()),  # fetch `cat`: bytes (no text=True)
        ])
        local_out = tmp_path / "e2e_acr_capture.json"
        rc, out, got = e2e.run_reader_cmd(
            ["python3", str(e2e.HERE / "capture.py"), "--output", str(local_out)],
            output=local_out,
        )
        assert rc == 0
        assert got == local_out and local_out.exists()
        assert json.loads(local_out.read_text())["reader"] == "x"
        # the remote command wrote to the scratch path, not the local path
        assert e2e.REMOTE_TMP in calls[0][6]
        assert str(local_out) not in calls[0][6]

    def test_remote_failure_is_reported(self, monkeypatch, tmp_path):
        self._install(monkeypatch, [_FakeProc(255, "", "ssh: connect refused")])
        local_out = tmp_path / "cap.json"
        rc, out, got = e2e.run_reader_cmd(["python3", "x.py", "--output", str(local_out)],
                                          output=local_out)
        assert rc == 255
        assert "refused" in out
        assert got is None and not local_out.exists()

    def test_fetch_failure_is_reported(self, monkeypatch, tmp_path):
        self._install(monkeypatch, [
            _FakeProc(0, "captured"),
            _FakeProc(1, stdout="", stderr="cat: no such file"),
        ])
        local_out = tmp_path / "cap.json"
        rc, out, got = e2e.run_reader_cmd(["python3", "x.py", "--output", str(local_out)],
                                          output=local_out)
        assert rc == -3
        assert "fetch failed" in out

    def test_ssh_timeout(self, monkeypatch, tmp_path):
        def fake_run(argv, **kw):
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=10)

        monkeypatch.setattr(e2e, "SSH_HOST", "bench-host")
        monkeypatch.setattr(e2e.subprocess, "run", fake_run)
        rc, out, got = e2e.run_reader_cmd(["python3", "x.py"], timeout=10)
        assert rc == -1 and "TIMEOUT" in out and got is None


class TestReaderInventory:
    def test_parses_json_inventory(self, monkeypatch):
        monkeypatch.setattr(e2e, "SSH_HOST", None)
        monkeypatch.setattr(
            e2e, "run_reader_cmd",
            lambda *a, **kw: (0, '["ACS ACR1252 [PICC]", "GemPCTwin"]\n', None),
        )
        names = e2e.reader_inventory()
        assert names == ["ACS ACR1252 [PICC]", "GemPCTwin"]

    def test_garbage_inventory_is_empty(self, monkeypatch):
        monkeypatch.setattr(e2e, "SSH_HOST", None)
        monkeypatch.setattr(e2e, "run_reader_cmd",
                            lambda *a, **kw: (0, "no pcsc readers\n", None))
        assert e2e.reader_inventory() == []

    def test_probe_command_emits_json(self, monkeypatch):
        seen = {}

        def fake_probe(cmd, **kw):
            seen["cmd"] = cmd
            return 0, "[]", None

        monkeypatch.setattr(e2e, "SSH_HOST", None)
        monkeypatch.setattr(e2e, "run_reader_cmd", fake_probe)
        e2e.reader_inventory()
        assert "json.dumps" in " ".join(seen["cmd"])
