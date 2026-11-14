"""vpicc_model: injectable read-window file data (downstream benches serve
their own NDEF through the model). Pure, host-safe."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpicc_model import Ntag424State, ModelVpicc, answer  # noqa: E402

GOLDEN_WINDOW = bytes.fromhex("004fd1014b5504626f6c7463617264")


def _read_first_window(state):
    # minimal ladder: select CC (E103), then read 15 bytes from 0
    r1 = answer(state, bytes.fromhex("00A4000C02E10300"))
    assert r1[-2:] == b"\x90\x00"
    return answer(state, bytes.fromhex("00B000000F"))


def test_default_window_is_the_golden_capture():
    out = _read_first_window(Ntag424State())
    assert out[:-2] == GOLDEN_WINDOW[:15]
    assert out[-2:] == b"\x90\x00"


def test_injected_window_is_served_verbatim():
    custom = bytes.fromhex("003d91e102cafe") + b"\x00" * 8
    state = Ntag424State(read_window_content=custom)
    out = _read_first_window(state)
    assert out == custom[:15] + b"\x90\x00"


def test_model_vpicc_passthrough_injects():
    custom = b"\x00" + b"\xaa" * 20
    card = ModelVpicc(read_window_content=custom)
    r1 = card.answer(bytes.fromhex("00A4000C02E10300"))
    assert r1[-2:] == b"\x90\x00"
    out = card.answer(bytes.fromhex("00B000000F"))
    assert out == custom[:15] + b"\x90\x00"
