"""Live drift check: do the bolty places' labgrid matches still resolve?

The 2026-10-25 ACR move to ai-legion-small left two fossils behind:
labgrid-place.sh kept ENSURING the retired ai-legion-nfc/ref-acr1252
match (re-breaking migrated places on every run), and
labgrid-state-places.sh targeted exporter groups that no longer exist.
Both were invisible until an acquire failed with "matches nothing".
This module turns that class of drift into a `make status` line.

Phantom rule: a match on an existing place that resolves to ZERO live
resources. A place that does not exist at all (documentation places are
wiped by coordinator restarts) is reported as missing, not phantom —
`make labgrid-place` / `make hil-state-places` recreate them.

Best-effort like hil.labgrid_state: coordinator down = one clear line,
never a crash (a status probe must not die on bench infra hiccups).
"""

import shutil
import subprocess

COORDINATOR = "192.168.13.208:20408"
TIMEOUT_S = 8
FALLBACK_CLIENT = "/home/ubuntu/src/fips-lab/.venv/bin/labgrid-client"

# bolty-rig/ref-acr1252: exclusivity places (labgrid-place.sh).
# bolty-m5stick/bolty-acr1252: documentation state-record places
# (labgrid-state-places.sh) — may legitimately vanish on coordinator
# restarts until the script reruns.
EXCLUSIVITY_PLACES = ("bolty-rig", "ref-acr1252")
DOC_PLACES = ("bolty-m5stick", "bolty-acr1252")


def _client_cmd() -> str:
    return "labgrid-client" if shutil.which("labgrid-client") else FALLBACK_CLIENT


def parse_show(text: str) -> tuple[list[str], set[str]]:
    """Split `labgrid-client -p P show` into (matches, resolved prefixes).

    matches: the 4-space-indented lines under 'matches:'
    resolved: prefixes of parenthesized Matching-resource paths
    """
    matches, resolved = [], set()
    in_matches = False
    for line in text.splitlines():
        if line.strip() == "matches:":
            in_matches = True
            continue
        if in_matches:
            if line.startswith("    ") and line.strip():
                matches.append(line.strip())
            elif line.strip():
                in_matches = False
        if line.lstrip().startswith("Matching resource"):
            path = line.split("(", 1)[1].split(")", 1)[0]
            resolved.add("/".join(path.split("/")[:3]))
    return matches, resolved


def check_place(place: str, _run=subprocess.run) -> dict:
    """One place's drift verdict: missing | ok | phantom(matches)."""
    try:
        proc = _run(
            [_client_cmd(), "-x", COORDINATOR, "-p", place, "show"],
            capture_output=True, text=True, timeout=TIMEOUT_S,
        )
    except Exception:  # noqa: BLE001 — status probe, never fatal
        return {"place": place, "state": "error", "detail": "client/coordinator unreachable"}
    if proc.returncode != 0 or "Place '" not in proc.stdout:
        return {"place": place, "state": "missing",
                "detail": "not on coordinator (recreate if expected)"}
    matches, resolved = parse_show(proc.stdout)
    phantoms = [m for m in matches if m not in resolved]
    if phantoms:
        return {"place": place, "state": "phantom", "detail": ", ".join(phantoms)}
    return {"place": place, "state": "ok",
            "detail": f"{len(matches)} match(es) resolve"}


def check_all(_run=subprocess.run) -> list[dict]:
    return [check_place(p, _run) for p in (*EXCLUSIVITY_PLACES, *DOC_PLACES)]


def main() -> int:
    reports = check_all()
    print("=== labgrid place drift ===")
    for r in reports:
        print(f"  [{r['state']:>7}] {r['place']}: {r['detail']}")
    hard = [r for r in reports
            if r["state"] == "phantom"
            or (r["state"] in ("error", "missing") and r["place"] in EXCLUSIVITY_PLACES)]
    if hard:
        print(f"DRIFT: {len(hard)} hard problem(s) — exclusivity places must "
              "resolve; run make labgrid-place / hil-state-places, then re-check")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
