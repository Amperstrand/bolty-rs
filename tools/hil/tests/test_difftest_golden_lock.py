"""Difftest golden reference-lock (host-CI safe, no hardware).

Port of the ntag424 reference-lock pattern (ntag424 commit 02f23f5 /
tests/shared_vectors.rs): the committed difftest golden and generated
fixtures are pinned by sha256 in difftest/results/LOCK, and this test
self-asserts both the file hashes and that the LOCK actually pins them.
A local edit or bad merge that silently re-baselines the differential
oracle now fails CI instead of quietly blessing drift.

Deliberate re-baseline procedure: see the header of difftest/results/LOCK.
"""

import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIFFTEST = HERE.parent / "difftest"

LOCKED_FILES = [
    "results/golden_acr1252.json",
    "results/golden_acr1252_card2.json",
    "generated/test_golden_responses.py",
    "generated/golden_responses.h",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def test_vendored_golden_is_reference_locked():
    lock = (DIFFTEST / "results" / "LOCK").read_text()
    pinned = dict(re.findall(r"^(\S+) sha256: ([0-9a-f]{64})$", lock, re.M))
    assert pinned, "LOCK parsed empty — format broken?"

    for rel in LOCKED_FILES:
        path = DIFFTEST / rel
        assert path.exists(), f"{rel} missing (was the oracle deleted?)"
        actual = _sha256(path)
        assert pinned.get(rel) == actual, (
            f"{rel} drifted from the reference-locked golden "
            f"(actual {actual}, LOCK pins {pinned.get(rel)}). If this is a "
            "deliberate re-baseline, refresh results/LOCK per its header."
        )
        # Self-asserting cross-check (LOCK must actually pin the file).
        assert f"{rel} sha256: {actual}" in lock
