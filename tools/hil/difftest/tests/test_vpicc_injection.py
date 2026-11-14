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


def _generic_type4_read(card, le_cc=15, le_ndef=0x20):
    """A generic Type-4 reader ladder (wallet-matrix probe_acr shape)."""
    assert card.answer(bytes.fromhex("00A4040007D276000085010100"))[-2:] == b"\x90\x00"
    assert card.answer(bytes.fromhex("00A4000C02E103"))[-2:] == b"\x90\x00"
    cc = card.answer(bytes([0x00, 0xB0, 0x00, 0x00, le_cc]))
    assert cc[-2:] == b"\x90\x00"
    assert card.answer(bytes.fromhex("00A4000C02E104"))[-2:] == b"\x90\x00"
    return cc[:-2], card.answer(bytes([0x00, 0xB0, 0x00, 0x00, le_ndef]))


def test_ndef_file_mode_reads_injected_message_like_silicon():
    ndef = bytes.fromhex("d1012b550174657374")  # minimal URI record 'test'
    card = ModelVpicc(ndef_file=ndef)
    cc, ndef_read = _generic_type4_read(card)
    assert cc == Ntag424State.CC_BYTES
    body = ndef_read[:-2]
    assert ndef_read[-2:] == b"\x90\x00"
    # length prefix (2B BE) + message, offset-aware, Le-truncated
    assert body == len(ndef).to_bytes(2, "big") + ndef


def test_ndef_file_mode_offset_windows_and_eof():
    ndef = b"\xaa" * 40
    card = ModelVpicc(ndef_file=ndef)
    card.answer(bytes.fromhex("00A4000C02E104"))
    first = card.answer(bytes([0x00, 0xB0, 0x00, 0x00, 0x20]))
    assert first[-2:] == b"\x90\x00" and len(first) == 0x20 + 2
    # offset 0x20 -> second half (budget: 2 reads so far, 3 allowed)
    second = card.answer(bytes([0x00, 0xB0, 0x00, 0x20, 0x20]))
    assert second[-2:] == b"\x90\x00"
    content = first[:-2] + second[:-2]
    assert content == len(ndef).to_bytes(2, "big") + ndef
    # past EOF -> 6A82
    card2 = ModelVpicc(ndef_file=b"\x01")
    card2.answer(bytes.fromhex("00A4000C02E104"))
    eof = card2.answer(bytes([0x00, 0xB0, 0x00, 0x05, 0x10]))
    assert eof[-2:] == b"\x6a\x82"


def test_default_mode_quirks_unchanged_with_ndef_file_unset():
    # offsets ignored + canned window: the pinned golden path
    state = Ntag424State()
    answer(state, bytes.fromhex("00A4000C02E103"))
    r = answer(state, bytes.fromhex("00B000040F"))  # offset 0x04 ignored
    assert r[:-2] == GOLDEN_WINDOW[:15]
