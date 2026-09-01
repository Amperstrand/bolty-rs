"""Role management: exception-safe context manager around role_switch.switch_to.

`with role_guard("ccid"):` switches to ccid and ALWAYS restores bolty on exit
(including on test failure/exception), recording both timelines. This encodes
the restore-always discipline the overnight harness proved (learnings.md:148).
"""

import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

OVERNIGHT_DIR = Path(__file__).resolve().parents[1] / "overnight"
RESULTS_ROOT = OVERNIGHT_DIR / "results"


@contextmanager
def role_guard(target: str, session: str | None = None) -> Iterator[dict]:
    """Switch the stick to `target` role; restore bolty on scope exit.

    Yields a dict: {"switch": result, "restore": None}.
    After the block, ["restore"] holds the restore result (ok, detail).
    Degraded outcomes (strict-verify fail on absent ACR1252) are tolerated
    if the target reader appeared; the restore uses the same tolerance plus
    the manual console-start fallback (perf-sprint precedent).
    """
    if "role_switch" not in sys.modules and str(OVERNIGHT_DIR) not in sys.path:
        sys.path.insert(0, str(OVERNIGHT_DIR))
    import role_switch  # noqa: PLC0415 — deliberately lazy; heavy module

    session = session or f"hil-framework-{uuid.uuid4().hex[:8]}"
    switch_dir = RESULTS_ROOT / session
    result = role_switch.switch_to(target, results_dir=str(switch_dir))
    payload: dict = {"switch": {"ok": result.ok, "detail": result.detail}}

    try:
        yield payload
    finally:
        restore = role_switch.switch_to("bolty", results_dir=str(switch_dir / "restore"))
        payload["restore"] = {"ok": restore.ok, "detail": restore.detail}
        if not restore.ok and "ACR1252" in restore.detail:
            # Degraded-mode completion (perf-sprint precedent): start the
            # console manually and PING — recorded, not fatal.
            import subprocess
            subprocess.run(
                ["sudo", "systemctl", "start", "bolty-console"],
                capture_output=True, timeout=30,
            )
            payload["restore"]["degraded"] = "manual console start (ACR absent)"


def degraded_ok(result: dict, reader_needle: str = "GemPCTwin") -> bool:
    """True if the role switch succeeded strictly OR degraded-only-on-ACR
    while the target reader appeared."""
    if result["ok"]:
        return True
    detail = result["detail"]
    return ("ACR1252" in detail and reader_needle.lower() in detail.lower()
            and "readers=" in detail)
