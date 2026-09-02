"""APDU coverage via bolty-cli against the ACR1252 — no role switch needed.

Runs e2e.py --phase bolty-acr: bolty-cli operations (diagnose, uid, url,
inspect) against the coupled card through the ACR1252. This gives APDU-level
coverage on every `make test-hil` at zero hardware-switching cost.
"""

import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.hardware

DIFFTEST_DIR = Path(__file__).resolve().parents[1] / "difftest"


def test_bolty_acr_apdu_coverage():
    """e2e.py bolty-acr phase: diagnose → uid → url → inspect through ACR."""
    out = subprocess.run(
        ["python3", "e2e.py", "--phase", "bolty-acr"],
        cwd=DIFFTEST_DIR, capture_output=True, text=True, timeout=300,
    )
    combined = out.stdout + out.stderr
    assert out.returncode == 0, f"bolty-acr phase failed:\n{combined[-1500:]}"
    assert "PASS" in combined or "ok" in combined.lower(), (
        f"bolty-acr phase did not pass:\n{combined[-1500:]}"
    )
