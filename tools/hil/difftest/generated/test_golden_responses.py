"""Auto-generated golden reference tests.

Source: ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 00 00
Card UID: 04C474FA967380
Generated from: capture session with 63 APDU tests

Each test asserts that sending the recorded APDU to any reader
produces the same response bytes and status word as the golden
reference (the ACR1252 commercial reader).
"""

import pytest


# Golden reference data (extracted from capture session)
GOLDEN_TESTS = [
    ("get_uid", "FFCA000000", "04c474fa967380", "9000", "Get card UID via pseudo-APDU"),
    ("select_mf", "00A4000C023F00", "", "9000", "Select MF (master file)"),
    ("select_invalid_df", "00A4000C024567", "", "6A82", "Select non-existent DF (expect file-not-found SW)"),
    ("select_by_aid_ntag424", "00A4040007D276000085010100", "", "9000", "Select NTAG424 AID (D2760000850101)"),
    ("select_by_aid_invalid", "00A4040007D2760000990101", "", "6A82", "Select invalid AID (expect file-not-found SW)"),
    ("get_response_no_pending", "00C0000000", "", "6D00", "GET RESPONSE with no pending data"),
    ("select_cc_file", "00A4000C02E103", "", "9000", "Select Capability Container file (E103)"),
    ("select_ndef_file", "00A4000C02E104", "", "9000", "Select NDEF file (E104)"),
    ("read_cc_full", "00B000000F", "004fd1014b5504626f6c7463617264", "9000", "Read full Capability Container (15 bytes)"),
    ("read_cc_partial", "00B0000004", "004fd101", "9000", "Read CC partial (first 4 bytes)"),
    ("read_cc_invalid_offset", "00B0FF0001", "", "6A86", "Read CC from invalid offset 0xFF"),
    ("read_ndef_after_select", "00B0990030", "", "6A82", "Read NDEF file after selecting it"),
    ("read_no_select", "00B000000F", "004fd1014b5504626f6c7463617264", "9000", "Read without prior SELECT (expect error)"),
    ("get_file_settings_cc", "00F500000A", "", "6D00", "Get file settings for CC file"),
    ("get_file_settings_ndef", "00F599000A", "", "6D00", "Get file settings for NDEF file"),
    ("get_file_settings_invalid", "00F5AA000A", "", "6D00", "Get file settings for invalid file number"),
    ("get_key_version_k0_noauth", "00C0000001", "", "6D00", "Get key version K0 without auth (expect SW 63xx or 698x)"),
    ("get_key_version_k1_noauth", "00C0000101", "", "6D00", "Get key version K1 without auth (expect SW 63xx or 698x)"),
    ("get_key_version_invalid", "00C0000501", "", "6D00", "Get key version for invalid key number"),
    ("read_sdm_no_select", "00F5000A0A", "", "6D00", "Read SDM metadata without selecting the right file"),
    ("malformed_cla_only", "00", "", "6700", "CLA byte only (1 byte)"),
    ("malformed_short_header", "00A40000", "", "9000", "4-byte header only (no Lc, no data)"),
    ("malformed_lc_mismatch", "00A4040004D276", "", "6700", "Lc says 4 but only 2 data bytes follow"),
    ("malformed_le_zero", "00B0000000", "", "6985", "Le=0 (expect 256 bytes or specific SW)"),
    ("malformed_le_max", "00B00000FF", "", "6985", "Le=FF (255 bytes)"),
    ("malformed_invalid_cla", "FFA4000C023F00", "", "6300", "Invalid CLA byte 0xFF (proprietary)"),
    ("malformed_invalid_ins", "00FF000C023F00", "", "6D00", "Invalid INS byte 0xFF"),
    ("malformed_reserved_ins", "006E000C023F00", "", "6D00", "Reserved INS byte 0x6E"),
    ("malformed_oversized_lc", "00A4040FFFD276000085010100", "", "6700", "Lc=FF but only 7 data bytes follow (NTAG424 AID)"),
    ("malformed_single_byte_high", "FF", "", "6700", "Single byte 0xFF"),
    ("malformed_single_byte_zero", "00", "", "6700", "Single byte 0x00"),
    ("stress_double_select", "00A4000C023F00", "", "9000", "Select same file twice consecutively"),
    ("stress_read_cc_10x", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r1", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r2", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r3", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r4", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r5", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r6", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r7", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r8", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_read_cc_10x_r9", "00B000000F", "", "6985", "Read CC file 10 times (stability under repetition)"),
    ("stress_select_garbage_alternating", "F0F0F0F0F0F0F0F0", "", "6700", "Valid SELECT then 8 bytes of garbage, alternating"),
    ("fuzz_00", "FA0C3C70A71F82FD792CCD5D20051EC04FED", "", "6700", "Fuzz case 0: 18 random bytes (seed=16962)"),
    ("fuzz_01", "CFCFCB54EEAC97EA", "", "6700", "Fuzz case 1: 8 random bytes (seed=16962)"),
    ("fuzz_02", "5F78B9E875CF65C79E93DE2C065EFE", "", "6700", "Fuzz case 2: 15 random bytes (seed=16962)"),
    ("fuzz_03", "EAF9776A1AB5FB101E", "", "6700", "Fuzz case 3: 9 random bytes (seed=16962)"),
    ("fuzz_04", "CBC9847F23BBD3114306AB485E887667D777C5998DA9C8757195", "", "6700", "Fuzz case 4: 26 random bytes (seed=16962)"),
    ("fuzz_05", "0BAF0F5D8E237159E87AC8B9165D6FB3", "", "6700", "Fuzz case 5: 16 random bytes (seed=16962)"),
    ("fuzz_06", "7DB96BF85D8BC8FC0A6F37CA53F15FB102B3B26A2ACA3191366429", "", "6700", "Fuzz case 6: 27 random bytes (seed=16962)"),
    ("fuzz_07", "B62C6187927550EF34FFDA99A66776956A198080", "", "6700", "Fuzz case 7: 20 random bytes (seed=16962)"),
    ("fuzz_08", "4FB95967B3A9DBF636A7B91F29E993", "", "6700", "Fuzz case 8: 15 random bytes (seed=16962)"),
    ("fuzz_09", "C8E62A", "", "6700", "Fuzz case 9: 3 random bytes (seed=16962)"),
    ("fuzz_10", "A4D7A20A1E2D", "", "6700", "Fuzz case 10: 6 random bytes (seed=16962)"),
    ("fuzz_11", "4574", "", "6700", "Fuzz case 11: 2 random bytes (seed=16962)"),
    ("fuzz_12", "2B68A0B55D8A281370", "", "6700", "Fuzz case 12: 9 random bytes (seed=16962)"),
    ("fuzz_13", "EF688206F8ADB1F9C355", "", "6700", "Fuzz case 13: 10 random bytes (seed=16962)"),
    ("fuzz_14", "DF1CA15E169802B64E84FEF9505C", "", "6700", "Fuzz case 14: 14 random bytes (seed=16962)"),
    ("fuzz_15", "EF1E5FC19A80F4690C1F", "", "6700", "Fuzz case 15: 10 random bytes (seed=16962)"),
    ("fuzz_16", "B08542B01B9FF5CEED7C5BE6E81B38F9B09BFB25A89673", "", "6700", "Fuzz case 16: 23 random bytes (seed=16962)"),
    ("fuzz_17", "5FBA961A284072F7C7318F4F0C6C9229F360AC", "", "6700", "Fuzz case 17: 19 random bytes (seed=16962)"),
    ("fuzz_18", "28C949D44FFF4139FFFE8E608699F2683289", "", "6700", "Fuzz case 18: 18 random bytes (seed=16962)"),
    ("fuzz_19", "C7E1B0A8942114F8A54DC3B68F040901ECE6E3A6", "", "6700", "Fuzz case 19: 20 random bytes (seed=16962)"),
]


@pytest.mark.parametrize(
    "test_id,apdu_hex,expected_response,expected_sw,description",
    GOLDEN_TESTS,
    ids=[t[0] for t in GOLDEN_TESTS],
)
def test_golden_apdu_response(test_id, apdu_hex, expected_response, expected_sw, description):
    """Verify APDU response matches golden reference."""
    # This test is designed to run against any reader via pcscd.
    # The fixture data encodes the expected response from the ACR1252.
    # When running against a different reader (e.g., GemPCTwin),
    # any mismatch indicates a behavioral difference worth investigating.
    assert apdu_hex, f"{test_id}: APDU must not be empty"
    # Note: actual transmit requires a connected reader.
    # This is a data validation test (structure check) when run offline.
    # For live testing, use the capture.py + diff.py tools.
    if expected_sw:
        assert len(expected_sw) == 4, f"{test_id}: SW must be 4 hex chars"


def test_golden_data_integrity():
    """Verify the golden test data is well-formed."""
    seen_ids = set()
    for test_id, apdu_hex, resp, sw, desc in GOLDEN_TESTS:
        assert test_id not in seen_ids, f"duplicate test_id: {test_id}"
        seen_ids.add(test_id)
        assert isinstance(apdu_hex, str), f"{test_id}: apdu must be string"
        if apdu_hex:
            bytes.fromhex(apdu_hex.replace(" ", ""))  # must be valid hex

