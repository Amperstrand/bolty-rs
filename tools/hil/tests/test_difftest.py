"""Difftest wrapper: the 66/66 APDU differential vs the ACR1252 golden.

Requires the ccid role on the stick (role_guard auto-restores). The golden
captures are committed; the comparison is card-aware (e2e handles selection).
"""

import subprocess
from pathlib import Path

import pytest

from hil.roles import role_guard, degraded_ok

pytestmark = [pytest.mark.hardware, pytest.mark.role_switch]

DIFFTEST_DIR = Path(__file__).resolve().parents[1] / "difftest"


def test_apdu_difftest_66_of_66():
    with role_guard("ccid") as ctx:
        assert degraded_ok(ctx["switch"], "GemPCTwin"), ctx["switch"]["detail"]
        out = subprocess.run(
            ["python3", "e2e.py", "--phase", "apdu"],
            cwd=DIFFTEST_DIR, capture_output=True, text=True, timeout=1800,
        )
        combined = out.stdout + out.stderr
        assert out.returncode == 0, f"difftest failed:\n{combined[-2000:]}"
        assert "66/66" in combined or "100%" in combined, (
            f"difftest did not reach 66/66:\n{combined[-2000:]}"
        )
    assert ctx["restore"]["ok"] or ctx["restore"].get("degraded"), ctx["restore"]
