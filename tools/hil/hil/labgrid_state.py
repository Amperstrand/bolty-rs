"""Labgrid state tagging (fips-lab pattern 15): mirror live rig state onto
the bolty-rig place tags so any bench session — including a nucula or
microfips one — can ask labgrid what the stick runs, instead of probing
serial prompts (docs/labgrid-bench-sharing.md P1). This would have made the
2026-09-03 nucula takeover visible as owner=nucula on the spot.

Best-effort by contract (gm65-scanner campaign.py place_tags lineage): a
coordinator hiccup mid-run must never kill a run — every failure mode is
swallowed, bounded by a short timeout.
"""

import shutil
import subprocess
import time

# Coordinator binds only this address (see labgrid-env.yaml); mDNS does not
# resolve on this host. Kept in sync with conftest.LABGRID_COORDINATOR.
COORDINATOR = "192.168.13.221:20408"
PLACE = "bolty-rig"
TIMEOUT_S = 5
# labgrid-client is on PATH on the bench host (~/.local/bin); the fips-lab
# venv install is the fallback on hosts where it is not.
FALLBACK_CLIENT = "/home/ubuntu/src/fips-lab/.venv/bin/labgrid-client"


def build_tags(
    test: str, firmware: str = "-", owner: str = "bolty-rs", now: float | None = None,
) -> list[str]:
    """The four state tags, in a stable order."""
    ts = time.strftime("%Y%m%dT%H%M%S", time.localtime(now if now is not None else time.time()))
    return [f"firmware={firmware}", f"test={test}", f"owner={owner}", f"ts={ts}"]


def _client_cmd() -> str:
    return "labgrid-client" if shutil.which("labgrid-client") else FALLBACK_CLIENT


def note_rig_state(
    test: str, firmware: str = "-", owner: str = "bolty-rs", _run=subprocess.run,
) -> None:
    """Tag the bolty-rig place with what it is currently running. Never
    fatal: client missing, coordinator down, timeout — all swallowed."""
    try:
        _run(
            [_client_cmd(), "-x", COORDINATOR, "-p", PLACE, "set-tags",
             *build_tags(test, firmware, owner)],
            capture_output=True, timeout=TIMEOUT_S,
        )
    except Exception:  # noqa: BLE001 — deliberate broad catch (pattern 15)
        pass
