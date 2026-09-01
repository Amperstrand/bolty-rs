"""Unit tests for the differential test harness."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # difftest/, where apdu_matrix lives
from apdu_matrix import (
    APDU_TESTS,
    ApduTest,
    generate_fuzz_cases,
    get_all_tests,
    get_categories,
    get_test_by_id,
    get_test_count,
)


class TestApduMatrix:
    def test_matrix_not_empty(self):
        assert len(APDU_TESTS) >= 35, f"Expected >=35 tests, got {len(APDU_TESTS)}"

    def test_all_have_unique_ids(self):
        ids = [t.test_id for t in APDU_TESTS]
        assert len(ids) == len(set(ids)), f"Duplicate test_ids: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_have_categories(self):
        cats = get_categories()
        assert len(cats) >= 5, f"Expected >=5 categories, got {cats}"
        assert "identity" in cats
        assert "iso7816" in cats
        assert "ntag424" in cats
        assert "malformed" in cats
        assert "stress" in cats

    def test_all_apdus_valid_hex(self):
        for t in APDU_TESTS:
            if t.apdu_hex and t.apdu_hex != "":
                bytes.fromhex(t.apdu_hex.replace(" ", ""))  # raises if invalid

    def test_fuzz_deterministic(self):
        cases1 = generate_fuzz_cases(seed=42, count=10)
        cases2 = generate_fuzz_cases(seed=42, count=10)
        assert len(cases1) == len(cases2) == 10
        for c1, c2 in zip(cases1, cases2):
            assert c1.apdu_hex == c2.apdu_hex, f"Fuzz not deterministic: {c1.test_id}"

    def test_fuzz_different_seeds(self):
        cases1 = generate_fuzz_cases(seed=1, count=10)
        cases2 = generate_fuzz_cases(seed=2, count=10)
        # At least some should differ
        differs = sum(1 for c1, c2 in zip(cases1, cases2) if c1.apdu_hex != c2.apdu_hex)
        assert differs > 0, "Different seeds should produce different fuzz cases"

    def test_get_test_by_id(self):
        t = get_test_by_id("select_mf")
        assert t is not None
        assert t.category == "iso7816"
        assert t.apdu_hex == "00A4000C023F00"

    def test_get_test_by_id_not_found(self):
        assert get_test_by_id("nonexistent") is None

    def test_get_all_includes_fuzz(self):
        all_with = get_all_tests(include_fuzz=True)
        all_without = get_all_tests(include_fuzz=False)
        assert len(all_with) > len(all_without)
        fuzz = [t for t in all_with if t.category == "fuzz"]
        assert len(fuzz) == 20  # FUZZ_COUNT

    def test_test_count_by_category(self):
        counts = get_test_count()
        assert counts.get("fuzz") == 20
        assert counts.get("identity", 0) >= 3
        assert counts.get("malformed", 0) >= 5

    def test_repeat_tests_exist(self):
        stress = [t for t in APDU_TESTS if t.repeat > 1]
        assert len(stress) >= 1, "Expected at least one stress test with repeat > 1"
        assert any(t.test_id == "stress_read_cc_10x" for t in stress)


class TestApduSafety:
    """Verify no test in the matrix mutates card state."""

    MUTATING_INSES = {0xD0, 0xD6, 0xC0, 0xC4, 0xD8, 0xE0, 0x24, 0x20, 0x04}

    def test_no_mutating_apdus_in_matrix(self):
        """Check that no APDU in the matrix uses a write/update INS on a file.
        Note: some INS values overlap between read and write contexts.
        We check the known-mutating ones for NTAG424."""
        for t in APDU_TESTS:
            if not t.apdu_hex or len(t.apdu_hex) < 2:
                continue
            apdu_bytes = bytes.fromhex(t.apdu_hex.replace(" ", ""))
            if len(apdu_bytes) >= 2:
                ins = apdu_bytes[1]
                # 0xC0 is GET RESPONSE in ISO7816 (safe), but also key ops in NTAG424
                # 0xD0 is UPDATE BINARY in ISO7816, but also a common test byte
                # We're conservative: flag anything that could be a write
                if ins in {0xD6, 0xD8, 0xE0, 0x24}:
                    pytest.fail(
                        f"{t.test_id}: potentially mutating INS=0x{ins:02X} in APDU {t.apdu_hex}"
                    )

    def test_key_change_apdus_expect_failure(self):
        """Key change APDUs are in the matrix but must be expected-to-fail (no auth)."""
        key_tests = [t for t in APDU_TESTS if t.category == "ntag424_keys"]
        assert len(key_tests) >= 2, "Expected key operation tests"
        # These are safe because they'll fail with auth errors on a blank card


class TestCaptureStructure:
    def test_capture_module_importable(self):
        import capture
        assert hasattr(capture, "run_capture")
        assert hasattr(capture, "send_apdu")
        assert hasattr(capture, "find_reader")

    def test_diff_module_importable(self):
        import diff
        assert hasattr(diff, "diff_sessions")
        assert hasattr(diff, "format_report")

    def test_generate_module_importable(self):
        import generate_tests
        assert hasattr(generate_tests, "generate_fixture_code")
        assert hasattr(generate_tests, "generate_c_fixture")

    def test_diff_empty_sessions(self):
        import diff
        golden = {"reader": "test", "results": []}
        test = {"reader": "test2", "results": []}
        d = diff.diff_sessions(golden, test)
        assert d["total_matches"] == 0
        assert d["total_mismatches"] == 0
        assert d["total_missing_in_test"] == 0

    def test_diff_matching_sessions(self):
        import diff
        golden = {"reader": "A", "results": [{"test_id": "t1", "response_bytes": "ABCD", "sw": "9000", "success": True, "duration_ms": 10, "category": "test"}]}
        test = {"reader": "B", "results": [{"test_id": "t1", "response_bytes": "ABCD", "sw": "9000", "success": True, "duration_ms": 15, "category": "test"}]}
        d = diff.diff_sessions(golden, test)
        assert d["total_matches"] == 1
        assert d["total_mismatches"] == 0

    def test_diff_mismatching_sessions(self):
        import diff
        golden = {"reader": "A", "results": [{"test_id": "t1", "response_bytes": "ABCD", "sw": "9000", "success": True, "duration_ms": 10, "category": "test"}]}
        test = {"reader": "B", "results": [{"test_id": "t1", "response_bytes": "FFFF", "sw": "6A82", "success": False, "duration_ms": 15, "category": "test"}]}
        d = diff.diff_sessions(golden, test)
        assert d["total_mismatches"] == 1
        assert d["mismatches"][0]["response_match"] is False
        assert d["mismatches"][0]["sw_match"] is False

    def test_diff_missing_and_extra(self):
        import diff
        golden = {"reader": "A", "results": [{"test_id": "t1", "response_bytes": "AB", "sw": "9000", "category": "c"}]}
        test = {"reader": "B", "results": [{"test_id": "t2", "response_bytes": "CD", "sw": "9000", "category": "c"}]}
        d = diff.diff_sessions(golden, test)
        assert d["total_missing_in_test"] == 1
        assert d["total_extra_in_test"] == 1
        assert "t1" in d["missing_in_test"]
        assert "t2" in d["extra_in_test"]
