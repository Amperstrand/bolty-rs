#!/usr/bin/env python3
"""vpicc_model — stateful pre-auth NTAG424 model (rung 1 of the design).

Answers C-APDUs COMPUTED FROM STATE where the rule is known, per
vpicc_model_design.md. The golden capture is this model's regression
test: with the model as answerer, every replayable golden exchange must
be byte-exact — behavior computed, only FILE DATA canned.

Rules are PINNED TO THE CAPTURE (each cites its golden test_id). Where
the recording shows behavior we cannot derive from a datasheet rule, the
model implements the EMPIRICAL rule and says so — the strongest claim is
"reproduces the recorded card", not "is the card".

Rule summary (golden 2026-08-29, card 04C474FA967380):

- default (fuzz/garbage/unparseable)            -> 6700   (fuzz_00..19,
                                                       stress_select_garbage)
- CLA 00 INS A4 SELECT:
    4-byte header (no Lc/data)                   -> 9000   (malformed_short_header)
    Lc != len(data) or Lc 0xFF                   -> 6700   (malformed_lc_mismatch,
                                                       malformed_oversized_lc)
    by FID (P1=00,P2=0C): 3F00 MF, E103 CC, E104 NDEF -> 9000
    by AID (P1=04): D2760000850101               -> 9000   (ntag424 app)
    anything else                                -> 6A82   (select_invalid_df,
                                                       select_by_aid_invalid)
- CLA 00 INS B0 READ BINARY:
    Le 00 or FF                                  -> 6985   (malformed_le_zero/max)
    offset 0xFF00.. (beyond file)                -> 6A86   (read_cc_invalid_offset)
    offset 0x99xx (NDEF-length window, this card)-> 6A82   (read_ndef_after_select)
    read budget not exhausted (first 2 reads)    -> Le-truncated CC-window
                                                   content + 9000
                                                   (read_cc_full, read_cc_partial,
                                                    read_no_select — note the
                                                   recorded bytes are the NDEF
                                                   URI record 'boltcard', an
                                                   empirical capture fact)
    read budget exhausted                        -> 6985   (stress_read_cc_10x r0-r9:
                                                   after the 2nd successful read
                                                   every later read 6985 — an
                                                   ANTI-HAMMERING-class empirical
                                                   rule, capture-pinned)
- CLA 00 other INS (C0,F5,FF,6E,...)             -> 6D00   (get_response_*,
                                                       get_file_settings_*,
                                                       get_key_version_*)
- CLA FF (non-CA; FFCA is reader-side and never
  reaches the card)                              -> 6300   (malformed_invalid_cla)
"""

from __future__ import annotations

from collections import deque

# Empirical capture facts (data, not behavior):
NTAG424_AID = bytes.fromhex("D2760000850101")
VALID_FIDS = {bytes.fromhex("3F00"): "MF", bytes.fromhex("E103"): "CC",
              bytes.fromhex("E104"): "NDEF"}
# The bytes the card served for in-window CC reads (Le-truncated on serve).
READ_WINDOW_CONTENT = bytes.fromhex("004fd1014b5504626f6c7463617264")
READ_BUDGET = 3  # successful content reads before the 6985 wall
# (full + partial + no_select served content; stress x10 then 6985)

SW = {"ok": b"\x90\x00", "lc": b"\x67\x00", "ins": b"\x6d\x00",
      "notfound": b"\x6a\x82", "offset": b"\x6a\x86",
      "cond": b"\x69\x85", "cla": b"\x63\x00"}


class Ntag424State:
    """Mutable model state (what the recorded card tracked)."""

    def __init__(self) -> None:
        self.selected: str | None = None
        self.reads_served = 0


def answer(state: Ntag424State, capdu: bytes) -> bytes:
    """Compute the R-APDU (data + SW) for a C-APDU. Rule citations in
    the module docstring; keep this dispatcher exactly as pinned."""
    if len(capdu) < 4:
        return SW["lc"]  # unparseable -> the capture's uniform default
    cla, ins, p1, p2 = capdu[0], capdu[1], capdu[2], capdu[3]
    body = capdu[4:]
    lc = body[0] if body else 0
    data = body[1:1 + lc] if lc else b""
    # case-4 SELECT legally carries one trailing Le byte (golden:
    # select_by_aid_ntag424 00A40400 07 <7B AID> 00); anything longer or
    # shorter than Lc (+optional Le) is the capture's 6700 class.
    lc_ok = len(body) in (1 + lc, 2 + lc)

    if cla == 0xFF:
        # FF CA is answered reader-side (never arrives); other FF-class
        # answered 6300 in the capture. All OTHER foreign CLAs fall
        # through to the uniform 6700 default (fuzz_00..19).
        if ins != 0xCA:
            return SW["cla"]

    if ins == 0xA4:  # SELECT
        if len(capdu) == 4:
            return SW["ok"]  # malformed_short_header pinned
        if not lc_ok:
            return SW["lc"]
        if p1 == 0x04:
            if data == NTAG424_AID:
                state.selected = "AID"
                return SW["ok"]
            return SW["notfound"]
        if p1 == 0x00 and p2 == 0x0C:
            fid = VALID_FIDS.get(data)
            if fid:
                state.selected = fid
                return SW["ok"]
            return SW["notfound"]
        return SW["lc"]  # garbage remainder class

    if cla != 0x00:
        return SW["lc"]  # foreign-CLA fuzz default (6700)

    if ins == 0xB0:  # READ BINARY
        le = capdu[-1]
        if le in (0x00, 0xFF):
            return SW["cond"]
        if p1 == 0xFF:
            return SW["offset"]
        if p1 == 0x99:
            return SW["notfound"]
        if state.reads_served >= READ_BUDGET:
            return SW["cond"]
        state.reads_served += 1
        return READ_WINDOW_CONTENT[:le] + SW["ok"]

    return SW["ins"]


class ModelVpicc:
    """Answerer adapter: plug into GoldenVpicc via ``answerer=``."""

    def __init__(self) -> None:
        self.state = Ntag424State()
        self.seen: deque[bytes] = deque(maxlen=64)

    def answer(self, capdu: bytes) -> bytes:
        self.seen.append(capdu)
        return answer(self.state, capdu)
