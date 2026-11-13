#!/usr/bin/env python3
"""Publish the Allure bench report off-host (Blossom + Nostr kind 30078).

Audit follow-up #3 (docs/cross-project-infra-audit-2026-11-12.md): Allure
reports and the run ledger live on lab hosts that reboot, move, or die
(the 2026-10-26 seat re-home lost console history). The cloudflareworker
line proved lab-outage-immune publication; this ports that pipeline to
bolty-rs evidence.

DRY-RUN IS THE DEFAULT: builds the artifact zip, pins its sha256, prints
the event that WOULD be published — zero network. Uploading/publishing
requires BOTH --publish and --nsec-file (nak CLI must be on PATH; the
same key/relay setup the prta/cloudflareworker lanes use).

    python3 -m publish.publish_allure                     # dry-run
    python3 -m publish.publish_allure --publish --nsec-file ~/.config/prta/nsec

The kind-30078 event is parameterized-replaceable (d = run timestamp), so
re-publishing a run replaces its index; file tags carry the Blossom URL,
and the sha256 lets any mirror verify the artifact (BUD-06 descriptor).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from blossom_publisher import compute_sha256  # noqa: E402
from nostr_publisher import publish_test_run_event  # noqa: E402
from blossom_publisher import upload_to_blossom  # noqa: E402

RESULTS = Path(__file__).resolve().parent.parent / "results"
REPORT_DIR = RESULTS / "allure-report"
LEDGER = RESULTS / "history.jsonl"
PROJECT_TAG = "bolty-hil"


def last_ledger_row() -> dict:
    """Newest run row (fail-soft: {} when absent/unreadable)."""
    try:
        rows = [json.loads(l) for l in LEDGER.read_text().splitlines() if l.strip()]
        return rows[-1] if rows else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def build_summary(ledger: dict, artifact: str, sha: str) -> str:
    if ledger:
        return (f"bolty-rs HIL run {ledger.get('ts', '?')}: "
                f"{ledger.get('passed', '?')} passed / {ledger.get('failed', '?')} "
                f"failed / {ledger.get('skipped', '?')} skipped "
                f"(exit {ledger.get('exit', '?')}) — artifact {artifact} "
                f"sha256:{sha[:16]}…")
    return f"bolty-rs HIL Allure report — artifact {artifact} sha256:{sha}"


def build_event_preview(run_id: str, file_urls: list, summary: str) -> dict:
    """The unsigned shape of the kind-30078 index event (dry-run output)."""
    tags = [["d", run_id], ["t", PROJECT_TAG],
            ["timestamp", str(int(time.time()))]]
    tags += [["file", u] for u in file_urls]
    return {"kind": 30078, "content": summary, "tags": tags}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--publish", action="store_true",
                    help="actually upload + publish (default: dry-run)")
    ap.add_argument("--nsec-file", default=None,
                    help="path to the Nostr key file (required with --publish)")
    ap.add_argument("--blossom-server",
                    default="https://blossom.psbt.me")
    args = ap.parse_args(argv)

    if not REPORT_DIR.is_dir():
        print(f"no Allure report at {REPORT_DIR} — run 'make report' first",
              file=sys.stderr)
        return 1

    run_id = time.strftime("bolty-%Y%m%d-%H%M%S")
    with tempfile.TemporaryDirectory(prefix="bolty-evidence-") as tmp:
        artifact = Path(tmp) / f"{run_id}.zip"
        with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(REPORT_DIR.rglob("*")):
                if p.is_file():
                    zf.write(p, p.relative_to(REPORT_DIR))
        sha = compute_sha256(str(artifact))
        size = artifact.stat().st_size
        summary = build_summary(last_ledger_row(), artifact.name, sha)

        if not args.publish:
            preview = build_event_preview(run_id, [], summary)
            print(f"[dry-run] artifact: {artifact.name} ({size} bytes)")
            print(f"[dry-run] sha256:  {sha}")
            print("[dry-run] event (unsigned):")
            print(json.dumps(preview, indent=1))
            print("[dry-run] no network was touched — pass --publish "
                  "--nsec-file <key> to upload")
            return 0

        if not args.nsec_file:
            print("--publish requires --nsec-file", file=sys.stderr)
            return 2
        url = upload_to_blossom(str(artifact), nsec_file=args.nsec_file,
                                server_url=args.blossom_server)["url"]
        print(f"uploaded: {url} (sha256 {sha})")
        event = publish_test_run_event(
            nsec_file=args.nsec_file, run_id=run_id, file_urls=[url],
            summary=summary, project_tag=PROJECT_TAG,
        )
        print("kind-30078 index event published:")
        print(json.dumps(event, indent=1))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
