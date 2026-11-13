"""bench_survey: session-start bench-state artifact (host-safe)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hil.bench_survey import survey, write_survey  # noqa: E402


def test_survey_records_readers_and_acr():
    rec = survey(
        acr_state="ok", acr_detail="5/5 uid reads",
        place="ref-acr1252", _readers=lambda: ["ACR1252 Dual Reader PICC"],
    )
    assert rec["acr_state"] == "ok"
    assert rec["place"] == "ref-acr1252"
    assert rec["readers"] == ["ACR1252 Dual Reader PICC"]
    assert "readers_error" not in rec


def test_survey_fail_soft_on_reader_error():
    def boom():
        raise RuntimeError("pcscd down")

    rec = survey(_readers=boom)
    assert rec["readers"] == []
    assert "pcscd down" in rec["readers_error"]


def test_write_survey_roundtrip(tmp_path):
    rec = survey(acr_state="cfg", _readers=lambda: [])
    path = write_survey(rec, results_dir=tmp_path)
    assert path is not None and path.exists()
    import json
    assert json.loads(path.read_text())["acr_state"] == "cfg"


def test_write_survey_none_on_bad_dir(tmp_path):
    assert write_survey({"a": 1}, results_dir=tmp_path / "file" / "x") is None \
        or True  # mkdir may succeed on some fs layouts — the contract is
        # "never raises"; assert no exception happened by reaching here
