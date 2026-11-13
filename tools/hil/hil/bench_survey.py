"""Session-start bench-state survey (wallet-matrix matrixctl pattern).

Audit follow-up #2 (docs/cross-project-infra-audit-2026-11-12.md):
HIL runs were not self-describing — card placement is volatile (AGENTS),
reader NVM state is a known silent killer (B33), yet nothing recorded
WHAT the bench looked like when the session started. The session-end
ledger row carries acr_state only; this survey adds the start snapshot:
pcscd reader inventory + the ACR probe verdict + place context, written
to results/bench-state-<ts>.json.

Fail-soft by contract (pattern-15 lineage): a survey must never gate or
kill a bench session — every failure mode degrades to a partial record.
"""

import json
import time
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def survey(acr_state: str | None = None, acr_detail: str | None = None,
           place: str | None = None, _readers=None) -> dict:
    """The start-of-session bench facts. Pure given injectable IO."""
    rec: dict = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "place": place,
        "acr_state": acr_state,
        "acr_detail": (acr_detail or "")[:160],
        "readers": [],
    }
    if _readers is None:
        def _readers():  # pragma: no cover - IO injection seam
            from smartcard.System import readers
            return [str(r) for r in readers()]
    try:
        rec["readers"] = _readers()
    except Exception as exc:  # noqa: BLE001 — fail-soft by contract
        rec["readers_error"] = repr(exc)[:120]
    return rec


def write_survey(data: dict, results_dir: Path = RESULTS_DIR) -> Path | None:
    """Best-effort artifact write; None on any IO problem."""
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
        path = results_dir / f"bench-state-{time.strftime('%Y%m%d-%H%M%S')}.json"
        with path.open("w") as fh:
            json.dump(data, fh, indent=1)
        return path
    except OSError:
        return None
