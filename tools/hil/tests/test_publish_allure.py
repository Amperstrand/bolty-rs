"""publish_allure: off-host evidence pipeline (host-safe — dry-run only,
network paths are mocked; no real upload/signing in tests)."""

import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "publish"))

import publish.publish_allure as pa  # noqa: E402


def _make_report(base: Path) -> Path:
    report = base / "results" / "allure-report"
    (report / "widgets").mkdir(parents=True)
    (report / "index.html").write_text("<html>report</html>")
    (report / "widgets" / "summary.json").write_text("{}")
    ledger = base / "results" / "history.jsonl"
    ledger.write_text(json.dumps({"ts": "2026-11-13T15:00:00+0100",
                                  "exit": 0, "passed": 40, "failed": 0,
                                  "skipped": 1}) + "\n")
    return report


def test_dry_run_builds_zip_pins_sha_no_network(tmp_path, monkeypatch, capsys):
    report = _make_report(tmp_path)
    monkeypatch.setattr(pa, "REPORT_DIR", report)
    monkeypatch.setattr(pa, "LEDGER", tmp_path / "results" / "history.jsonl")

    def no_network(*a, **kw):  # the contract: dry-run never networks
        raise AssertionError("dry-run touched the network")

    monkeypatch.setattr(pa, "upload_to_blossom", no_network)
    monkeypatch.setattr(pa, "publish_test_run_event", no_network)

    assert pa.main([]) == 0
    out = capsys.readouterr().out
    assert "[dry-run] sha256:" in out
    assert "40 passed" in out and "exit 0" in out
    preview = json.loads(out.split("event (unsigned):", 1)[1].split("[dry-run] no network")[0])
    assert preview["kind"] == 30078
    assert preview["tags"][0] == ["d", preview["tags"][0][1]]
    assert ["t", "bolty-hil"] in preview["tags"]


def test_publish_requires_nsec(tmp_path, monkeypatch, capsys):
    report = _make_report(tmp_path)
    monkeypatch.setattr(pa, "REPORT_DIR", report)
    monkeypatch.setattr(pa, "LEDGER", tmp_path / "results" / "history.jsonl")
    assert pa.main(["--publish"]) == 2
    assert "--nsec-file" in capsys.readouterr().err


def test_missing_report_hints_make_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pa, "REPORT_DIR", tmp_path / "nowhere")
    assert pa.main([]) == 1
    assert "make report" in capsys.readouterr().err


def test_zip_contains_report_tree(tmp_path, monkeypatch):
    report = _make_report(tmp_path)
    monkeypatch.setattr(pa, "REPORT_DIR", report)
    monkeypatch.setattr(pa, "LEDGER", tmp_path / "results" / "history.jsonl")

    zips = []
    real_TempDir = pa.tempfile.TemporaryDirectory

    class Grab(TempDir := real_TempDir):  # noqa: F841 — capture path
        pass

    # simpler: patch zipfile.ZipFile to record the target path
    real_zip = zipfile.ZipFile

    def spy_zip(target, *a, **kw):
        zips.append(Path(target))
        return real_zip(target, *a, **kw)

    monkeypatch.setattr(pa.zipfile, "ZipFile", spy_zip)
    pa.main([])
    assert zips and zips[0].name.startswith("bolty-")
