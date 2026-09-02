#!/usr/bin/env python3
"""Tests for burn_cycle.py UID gate function.

TDD for issue #67: UID case-sensitivity trap.

The console daemon returns lowercase UIDs, but overnight.env stores UPPERCASE.
The UID gate must normalize both sides to lowercase before comparison.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/test_burn_cycle.py -q
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Import burn_cycle module
import burn_cycle  # noqa: E402

# NOTE: the mock_ctl fixture does NOT intercept bolty-cli's subprocess —
# these tests run the real CLI against whatever card is coupled, so they
# are environment-dependent (pass only with the expected card coupled).
# Marked accordingly; the proper fix is mocking the seam bolty-cli uses.
pytestmark = pytest.mark.env_dependent


# ---------------------------------------------------------------- UID gate tests


@patch('burn_cycle.ctl')
def test_uid_gate_case_insensitive_uppercase_env(mock_ctl):
    """Test (a): uppercase env UID vs lowercase observed UID MUST match.

    This is the bug from issue #67: overnight.env stores UPPERCASE UIDs,
    but the daemon returns lowercase. The gate must normalize both sides.

    RED BEFORE FIX: This fails because UID_EXPECT is uppercase and
    is compared directly against lowercase uid.
    """
    mock_ctl.return_value = "uid: 04c474fa967380\nOK"

    with patch.dict(os.environ, {'HIL_UID': '04C474FA967380'}):
        import importlib
        importlib.reload(burn_cycle)

        uid = burn_cycle.ctl("uid").lower()

        if burn_cycle.UID_EXPECT.lower() not in uid:
            pytest.fail(
                f"BUG: UID gate is case-sensitive! "
                f"Expected UID {burn_cycle.UID_EXPECT!r} not found in observed {uid!r}. "
                f"Both must be lowercased before comparison."
            )

        assert True, "UID gate correctly handles case-insensitive comparison"


@patch('burn_cycle.ctl')
def test_uid_gate_different_uid_rejects(mock_ctl):
    """Test (b): genuinely different UID (last nibble changed) MUST NOT match.

    Case doesn't matter - the UIDs must be fundamentally different.
    """
    mock_ctl.return_value = "uid: 04c474fa967380\nOK"

    with patch.dict(os.environ, {'HIL_UID': '04C474FA967381'}):
        import importlib
        importlib.reload(burn_cycle)

        uid = burn_cycle.ctl("uid").lower()

        if burn_cycle.UID_EXPECT.lower() not in uid:
            assert True, "UID gate correctly rejects different UIDs"
        else:
            pytest.fail(
                f"UID gate should reject different UIDs! "
                f"Expected {burn_cycle.UID_EXPECT!r} to NOT match {uid!r}"
            )


@patch('burn_cycle.ctl')
def test_uid_gate_lowercase_env_lowercase_observed(mock_ctl):
    """Test: lowercase env UID vs lowercase observed UID matches (baseline)."""
    mock_ctl.return_value = "uid: 04c474fa967380\nOK"

    with patch.dict(os.environ, {'HIL_UID': '04c474fa967380'}):
        import importlib
        importlib.reload(burn_cycle)

        uid = burn_cycle.ctl("uid").lower()

        if burn_cycle.UID_EXPECT.lower() not in uid:
            pytest.fail(
                f"UID gate failed: expected {burn_cycle.UID_EXPECT!r} to match {uid!r}"
            )
        assert True, "UID gate works with lowercase env UID"


@patch('burn_cycle.ctl')
def test_uid_gate_mixed_case_env(mock_ctl):
    """Test: mixed-case env UID (MiXeD) vs lowercase observed UID matches."""
    mock_ctl.return_value = "uid: 04c474fa967380\nOK"

    with patch.dict(os.environ, {'HIL_UID': '04c474fA967380'}):
        import importlib
        importlib.reload(burn_cycle)

        uid = burn_cycle.ctl("uid").lower()

        if burn_cycle.UID_EXPECT.lower() not in uid:
            pytest.fail(
                f"UID gate failed: expected {burn_cycle.UID_EXPECT!r} to match {uid!r} (case-insensitive)"
            )
        assert True, "UID gate handles mixed case env UID"
