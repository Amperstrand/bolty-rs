"""labgrid_drift: phantom-match detection for the bolty places (host-CI
safe — pure parser tests against canned `show` output; no coordinator)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hil.labgrid_drift import check_all, check_place, parse_show  # noqa: E402


SHOW_OK = """Place 'bolty-rig':
  aliases: bolty
  tags: firmware=-, owner=bolty-rs
  matches:
    ai-legion-nfc/m5stick-usb/SerialPort
    ai-legion-small-nfc/acr1252/NetworkSmartcardReader
  acquired: None
Matching resource 'SerialPort' (ai-legion-nfc/m5stick-usb/SerialPort/SerialPort):
  {'avail': True}
Matching resource 'NetworkSmartcardReader' (ai-legion-small-nfc/acr1252/NetworkSmartcardReader/NetworkSmartcardReader):
  {'avail': True}
"""

SHOW_PHANTOM = """Place 'bolty-rig':
  matches:
    ai-legion-nfc/m5stick-usb/SerialPort
    ai-legion-nfc/ref-acr1252/USBDevice
  acquired: None
Matching resource 'SerialPort' (ai-legion-nfc/m5stick-usb/SerialPort/SerialPort):
  {'avail': True}
"""


class FakeRun:
    def __init__(self, replies):
        self.replies = replies

    def __call__(self, cmd, **kw):
        place = cmd[cmd.index("-p") + 1]
        rc, out = self.replies.get(place, (1, ""))
        return type("P", (), {"returncode": rc, "stdout": out})()


def test_parse_show_matches_and_resolved():
    matches, resolved = parse_show(SHOW_OK)
    assert matches == [
        "ai-legion-nfc/m5stick-usb/SerialPort",
        "ai-legion-small-nfc/acr1252/NetworkSmartcardReader",
    ]
    assert resolved == {
        "ai-legion-nfc/m5stick-usb/SerialPort",
        "ai-legion-small-nfc/acr1252/NetworkSmartcardReader",
    }


def test_check_place_ok():
    run = FakeRun({"bolty-rig": (0, SHOW_OK)})
    assert check_place("bolty-rig", _run=run)["state"] == "ok"


def test_check_place_phantom():
    run = FakeRun({"bolty-rig": (0, SHOW_PHANTOM)})
    r = check_place("bolty-rig", _run=run)
    assert r["state"] == "phantom"
    assert "ai-legion-nfc/ref-acr1252/USBDevice" in r["detail"]


def test_check_place_missing():
    run = FakeRun({"bolty-m5stick": (1, "Place not found")})
    r = check_place("bolty-m5stick", _run=run)
    assert r["state"] == "missing"


def test_check_all_only_phantom_and_missing_exclusivity_are_hard():
    run = FakeRun({
        "bolty-rig": (0, SHOW_OK),
        "ref-acr1252": (0, SHOW_OK),
        "bolty-m5stick": (1, ""),          # doc place missing → soft
        "bolty-acr1252": (0, SHOW_PHANTOM)  # doc place phantom → hard
    })
    states = {r["place"]: r["state"] for r in check_all(_run=run)}
    assert states["bolty-m5stick"] == "missing"
    assert states["bolty-acr1252"] == "phantom"
