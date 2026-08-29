"""APDU test matrix for NTAG424 DNA differential testing.

Each test defines an APDU to send and metadata about what it tests.
The matrix is designed to be sent to ANY reader (ACR1252 or GemPCTwin)
with the responses recorded for comparison.

Categories:
  identity     — card identification (UID, ATR)
  iso7816      — standard ISO 7816 commands
  ntag424      — NTAG424-specific file operations
  ntag424_keys — key operations (expect failures on blank card)
  ntag424_sdm  — SDM operations (expect failures without auth)
  malformed    — edge cases, protocol violations
  stress       — sequencing and repeated operations
  fuzz         — deterministic random bytes (seeded)

Card safety: ALL tests are read-only or expected-to-fail.
No test mutates card state. The proven-safe envelope holds.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ApduTest:
    test_id: str
    category: str
    description: str
    apdu_hex: str | None
    prerequisites: list[str] = field(default_factory=list)
    repeat: int = 1
    special: str | None = None
    card_dependent: bool = False  # if True, response bytes depend on card content


# ---------------------------------------------------------------------------
# Main test matrix
# ---------------------------------------------------------------------------

APDU_TESTS: list[ApduTest] = [
    # --- Card identification ---
    ApduTest(
        test_id="get_atr",
        card_dependent=True,
        category="identity",
        description="Get ATR (card answer-to-reset on connect)",
        apdu_hex=None,
        special="get_atr",
    ),
    ApduTest(
        test_id="get_uid",
        category="identity",
        description="Get card UID via pseudo-APDU",
        apdu_hex="FFCA000000",
        special="get_uid",
        card_dependent=True,
    ),
    ApduTest(
        test_id="reconnect_atr",
        card_dependent=True,
        category="identity",
        description="Reconnect and get ATR again (stability check)",
        apdu_hex=None,
        special="reconnect",
    ),

    # --- ISO 7816 basic commands ---
    ApduTest(
        test_id="select_mf",
        category="iso7816",
        description="Select MF (master file)",
        apdu_hex="00A4000C023F00",
    ),
    ApduTest(
        test_id="select_invalid_df",
        category="iso7816",
        description="Select non-existent DF (expect file-not-found SW)",
        apdu_hex="00A4000C024567",
    ),
    ApduTest(
        test_id="select_by_aid_ntag424",
        category="iso7816",
        description="Select NTAG424 AID (D2760000850101)",
        apdu_hex="00A4040007D276000085010100",
    ),
    ApduTest(
        test_id="select_by_aid_invalid",
        category="iso7816",
        description="Select invalid AID (expect file-not-found SW)",
        apdu_hex="00A4040007D2760000990101",
    ),
    ApduTest(
        test_id="get_response_no_pending",
        category="iso7816",
        description="GET RESPONSE with no pending data",
        apdu_hex="00C0000000",
    ),
    ApduTest(
        test_id="select_cc_file",
        category="ntag424",
        description="Select Capability Container file (E103)",
        apdu_hex="00A4000C02E103",
    ),
    ApduTest(
        test_id="select_ndef_file",
        category="ntag424",
        description="Select NDEF file (E104)",
        apdu_hex="00A4000C02E104",
    ),

    # --- NTAG424 file operations (after SELECT) ---
    ApduTest(
        test_id="read_cc_full",
        card_dependent=True,
        category="ntag424",
        description="Read full Capability Container (15 bytes)",
        apdu_hex="00B000000F",
        prerequisites=["select_cc_file"],
    ),
    ApduTest(
        test_id="read_cc_partial",
        card_dependent=True,
        category="ntag424",
        description="Read CC partial (first 4 bytes)",
        apdu_hex="00B0000004",
        prerequisites=["select_cc_file"],
    ),
    ApduTest(
        test_id="read_cc_invalid_offset",
        card_dependent=True,
        category="ntag424",
        description="Read CC from invalid offset 0xFF",
        apdu_hex="00B0FF0001",
        prerequisites=["select_cc_file"],
    ),
    ApduTest(
        test_id="read_ndef_after_select",
        card_dependent=True,
        category="ntag424",
        description="Read NDEF file after selecting it",
        apdu_hex="00B0990030",
        prerequisites=["select_ndef_file"],
    ),
    ApduTest(
        test_id="read_no_select",
        card_dependent=True,
        category="ntag424",
        description="Read without prior SELECT (expect error)",
        apdu_hex="00B000000F",
    ),
    ApduTest(
        test_id="get_file_settings_cc",
        category="ntag424",
        description="Get file settings for CC file",
        apdu_hex="00F500000A",
        prerequisites=["select_cc_file"],
    ),
    ApduTest(
        test_id="get_file_settings_ndef",
        category="ntag424",
        description="Get file settings for NDEF file",
        apdu_hex="00F599000A",
        prerequisites=["select_ndef_file"],
    ),
    ApduTest(
        test_id="get_file_settings_invalid",
        category="ntag424",
        description="Get file settings for invalid file number",
        apdu_hex="00F5AA000A",
    ),

    # --- Key operations (blank card — expect failures) ---
    ApduTest(
        test_id="get_key_version_k0_noauth",
        category="ntag424_keys",
        description="Get key version K0 without auth (expect SW 63xx or 698x)",
        apdu_hex="00C0000001",
    ),
    ApduTest(
        test_id="get_key_version_k1_noauth",
        category="ntag424_keys",
        description="Get key version K1 without auth (expect SW 63xx or 698x)",
        apdu_hex="00C0000101",
    ),
    ApduTest(
        test_id="get_key_version_invalid",
        category="ntag424_keys",
        description="Get key version for invalid key number",
        apdu_hex="00C0000501",
    ),

    # --- SDM operations (expect failures without auth) ---
    ApduTest(
        test_id="read_sdm_no_select",
        category="ntag424_sdm",
        description="Read SDM metadata without selecting the right file",
        apdu_hex="00F5000A0A",
    ),

    # --- Malformed / edge-case APDUs ---
    ApduTest(
        test_id="malformed_empty",
        category="malformed",
        description="Empty APDU (0 bytes)",
        apdu_hex="",
    ),
    ApduTest(
        test_id="malformed_cla_only",
        category="malformed",
        description="CLA byte only (1 byte)",
        apdu_hex="00",
    ),
    ApduTest(
        test_id="malformed_short_header",
        category="malformed",
        description="4-byte header only (no Lc, no data)",
        apdu_hex="00A40000",
    ),
    ApduTest(
        test_id="malformed_lc_mismatch",
        category="malformed",
        description="Lc says 4 but only 2 data bytes follow",
        apdu_hex="00A4040004D276",
    ),
    ApduTest(
        test_id="malformed_le_zero",
        category="malformed",
        description="Le=0 (expect 256 bytes or specific SW)",
        apdu_hex="00B0000000",
        prerequisites=["select_cc_file"],
    ),
    ApduTest(
        test_id="malformed_le_max",
        category="malformed",
        description="Le=FF (255 bytes)",
        apdu_hex="00B00000FF",
        prerequisites=["select_cc_file"],
    ),
    ApduTest(
        test_id="malformed_invalid_cla",
        category="malformed",
        description="Invalid CLA byte 0xFF (proprietary)",
        apdu_hex="FFA4000C023F00",
    ),
    ApduTest(
        test_id="malformed_invalid_ins",
        category="malformed",
        description="Invalid INS byte 0xFF",
        apdu_hex="00FF000C023F00",
    ),
    ApduTest(
        test_id="malformed_reserved_ins",
        category="malformed",
        description="Reserved INS byte 0x6E",
        apdu_hex="006E000C023F00",
    ),
    ApduTest(
        test_id="malformed_oversized_lc",
        category="malformed",
        description="Lc=FF but only 7 data bytes follow (NTAG424 AID)",
        apdu_hex="00A4040FFFD276000085010100",
    ),
    ApduTest(
        test_id="malformed_single_byte_high",
        category="malformed",
        description="Single byte 0xFF",
        apdu_hex="FF",
    ),
    ApduTest(
        test_id="malformed_single_byte_zero",
        category="malformed",
        description="Single byte 0x00",
        apdu_hex="00",
    ),

    # --- Protocol stress ---
    ApduTest(
        test_id="stress_double_select",
        category="stress",
        description="Select same file twice consecutively",
        apdu_hex="00A4000C023F00",
        prerequisites=["select_mf"],
    ),
    ApduTest(
        test_id="stress_read_cc_10x",
        category="stress",
        description="Read CC file 10 times (stability under repetition)",
        apdu_hex="00B000000F",
        prerequisites=["select_cc_file"],
        repeat=10,
    ),
    ApduTest(
        test_id="stress_select_garbage_alternating",
        category="stress",
        description="Valid SELECT then 8 bytes of garbage, alternating",
        apdu_hex="F0F0F0F0F0F0F0F0",
        prerequisites=["select_mf"],
    ),
]


# ---------------------------------------------------------------------------
# Deterministic fuzz cases (seeded for reproducibility)
# ---------------------------------------------------------------------------

FUZZ_SEED = 0x4242  # deterministic
FUZZ_COUNT = 20
FUZZ_MIN_LEN = 1
FUZZ_MAX_LEN = 32


def generate_fuzz_cases(seed: int = FUZZ_SEED, count: int = FUZZ_COUNT) -> list[ApduTest]:
    """Generate deterministic random-byte APDUs for protocol fuzzing."""
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        length = rng.randint(FUZZ_MIN_LEN, FUZZ_MAX_LEN)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        cases.append(
            ApduTest(
                test_id=f"fuzz_{i:02d}",
                category="fuzz",
                description=f"Fuzz case {i}: {length} random bytes (seed={seed})",
                apdu_hex=data.hex().upper(),
            )
        )
    return cases


def get_all_tests(include_fuzz: bool = True) -> list[ApduTest]:
    """Return the complete test matrix, optionally including fuzz cases."""
    tests = list(APDU_TESTS)
    if include_fuzz:
        tests.extend(generate_fuzz_cases())
    return tests


def get_test_by_id(test_id: str) -> ApduTest | None:
    """Find a test by its ID."""
    for t in get_all_tests():
        if t.test_id == test_id:
            return t
    return None


def get_categories() -> list[str]:
    """Return all unique categories in the matrix."""
    return sorted({t.category for t in APDU_TESTS})


def get_test_count() -> dict[str, int]:
    """Return test count by category."""
    from collections import Counter

    counts = Counter(t.category for t in get_all_tests())
    return dict(counts)
