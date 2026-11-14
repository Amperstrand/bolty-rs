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
GOLDEN_UID = bytes.fromhex("04c474fa967380")  # golden get_uid (FFCA reaches the card over vpcd)
# (full + partial + no_select served content; stress x10 then 6985)

SW = {"ok": b"\x90\x00", "lc": b"\x67\x00", "ins": b"\x6d\x00",
      "notfound": b"\x6a\x82", "offset": b"\x6a\x86",
      "cond": b"\x69\x85", "cla": b"\x63\x00"}


class Ntag424State:
    """Mutable model state (what the recorded card tracked).

    read_window_content: the bytes served for in-window content reads.
    Default is the golden capture's canned CC/NDEF window; downstream
    benches inject their own NDEF (e.g. a cashu request record) so the
    model can stand in for THEIR card — behavior stays computed, only
    FILE DATA is data (the design's own rule).

    ndef_file: OPTIONAL plain-read file model. When set (raw NDEF
    message bytes, no length prefix), READ BINARY becomes offset-aware
    against a virtual file set {E103: standard CC, E104: len+ndef} —
    a generic Type-4 reader ladder (SELECT AID → SELECT CC → READ CC →
    SELECT NDEF → READ NDEF) reads the injected message like real
    silicon, within the same READ_BUDGET. Default None = the golden
    card's empirical quirks exactly (offsets ignored, canned window,
    0x99 wall) — the 57/57 gate pins that path unchanged.
    """

    CC_BYTES = bytes.fromhex("000F1020003B00340600" + "00" * 5)[:15]
    NDEF_FID = bytes.fromhex("E104")

    def __init__(self, read_window_content: bytes | None = None,
                 ndef_file: bytes | None = None) -> None:
        self.selected: str | None = None
        self.reads_served = 0
        self.read_window: bytes = (
            READ_WINDOW_CONTENT if read_window_content is None
            else read_window_content
        )
        self.ndef_file = ndef_file


def answer(state: Ntag424State, capdu: bytes) -> bytes:
    """Compute the R-APDU (data + SW) for a C-APDU. Rule citations in
    the module docstring; keep this dispatcher exactly as pinned."""
    if len(capdu) < 4:
        return SW["lc"]  # unparseable -> the capture's uniform default
    cla, ins, p1, p2 = capdu[0], capdu[1], capdu[2], capdu[3]

    if cla == 0xFF and ins == 0xCA:
        # GET-UID pseudo-APDU: reader-side on the ACR, but over vpcd it IS
        # forwarded to the card (bench-verified 2026-10-31) — serve the
        # golden UID so host tools display it (golden: get_uid).
        return GOLDEN_UID + SW["ok"]
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
        if state.ndef_file is not None:
            # Plain-read file model: offset-aware serving of the virtual
            # file set, selected-file scoped (CC window pre-select too —
            # generic ladders read CC after SELECT E103).
            off = ((p1 & 0x3F) << 8) | p2  # 15-bit per Type-4 short-LE reads
            if state.selected == "NDEF":
                content = len(state.ndef_file).to_bytes(2, "big") + state.ndef_file
            else:
                content = Ntag424State.CC_BYTES
            state.reads_served += 1
            window = content[off:off + le]
            if not window:
                return SW["notfound"]  # past EOF
            return window + SW["ok"]
        state.reads_served += 1
        return state.read_window[:le] + SW["ok"]

    return SW["ins"]


class ModelVpicc:
    """Answerer adapter: plug into GoldenVpicc via ``answerer=``.

    Rung 2: CLA-90 security commands (AuthenticateEV2) are answered by the
    AuthEngine (card-side handshake, AN12196-pinned); everything else by
    the pre-auth rules. An engine per ModelVpicc = one handshake context.
    """

    def __init__(self, read_window_content: bytes | None = None,
                 ndef_file: bytes | None = None) -> None:
        self.state = Ntag424State(read_window_content, ndef_file)
        try:
            from vpicc_model_auth import AuthEngine
            self.auth = AuthEngine()
        except ImportError:  # pycryptodome absent -> pre-auth only
            self.auth = None
        self.seen: deque[bytes] = deque(maxlen=64)

    def reset(self) -> None:
        """Card reset (ATR probe): drop any in-flight handshake."""
        if self.auth is not None:
            self.auth.pending = None

    def answer(self, capdu: bytes) -> bytes:
        self.seen.append(capdu)
        if self.auth is not None and capdu[:1] == b"\x90":
            r = self.auth.answer(capdu)
            if r:
                return r
        return answer(self.state, capdu)
