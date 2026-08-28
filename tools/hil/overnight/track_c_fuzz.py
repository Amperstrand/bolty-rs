#!/usr/bin/env python3
"""Overnight Track C hook: timeboxed cargo-fuzz runs for ccid-firmware-rs.

Runs `cargo +nightly fuzz run <target> <corpus> -- -max_total_time=N` in the
ccid-firmware-rs repo, captures the full output to a log, copies any
crash-/timeout-/oom-/leak- artifacts produced during the run into
results/fuzz/artifacts/, and appends one JSON row per run to
results/fuzz/runs.jsonl. The per-target corpus persists across runs under
results/fuzz/corpus/<target>/ so overnight runs build on each other.

A crash is a FINDING, never a harness failure: it is recorded with status
"crash" plus the copied artifact paths, and the wrapper exits 3 so callers
can tell it apart from a clean run (exit 0) or a harness error (exit 1).

Usage:
  python3 tools/hil/overnight/track_c_fuzz.py --target fuzz_atr_parse --seconds 60
  python3 tools/hil/overnight/track_c_fuzz.py --target fuzz_serial_frame_parser --seconds 1200
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE.parents[3] / "ccid-firmware-rs"
DEFAULT_RESULTS = HERE / "results" / "fuzz"
ARTIFACT_PREFIXES = ("crash-", "timeout-", "oom-", "leak-")
# First build of the fuzz workspace (libfuzzer + sanitizer) can take minutes;
# the fuzz run itself is bounded by -max_total_time.
BUILD_BUDGET_S = 1800


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(row) + "\n")


def collect_artifacts(artifacts_dir: Path, run_start: float, dest: Path, target: str) -> list:
    # cargo-fuzz 0.13 writes findings to per-target subdirectories
    # (fuzz/artifacts/<target>/crash-<sha1>), so scan recursively.
    found = []
    if not artifacts_dir.is_dir():
        return found
    for entry in sorted(artifacts_dir.rglob("*")):
        if not entry.is_file() or not entry.name.startswith(ARTIFACT_PREFIXES):
            continue
        if entry.stat().st_mtime < run_start:
            continue
        dest.mkdir(parents=True, exist_ok=True)
        copied = dest / f"{target}-{entry.name}"
        shutil.copy2(entry, copied)
        found.append(str(copied))
    return found


def run_fuzz(target: str, seconds: int, repo: Path, corpus_dir: Path):
    cmd = ["cargo", "+nightly", "fuzz", "run", target, str(corpus_dir),
           "--", f"-max_total_time={seconds}"]
    started = time.time()
    proc = subprocess.Popen(cmd, cwd=repo, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=BUILD_BUDGET_S + seconds + 60)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, _ = proc.communicate()
        rc = -9
    return cmd, out, rc, started


def main() -> int:
    ap = argparse.ArgumentParser(description="Timeboxed cargo-fuzz runner hook (Track C)")
    ap.add_argument("--target", required=True,
                    help="fuzz target name (fuzz_atr_parse, fuzz_serial_frame_parser)")
    ap.add_argument("--seconds", type=int, required=True,
                    help="-max_total_time budget in seconds")
    ap.add_argument("--repo", type=Path, default=DEFAULT_REPO,
                    help="ccid-firmware-rs checkout (default: sibling repo)")
    ap.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS,
                    help="results/fuzz dir (rows, logs, artifacts, corpus)")
    args = ap.parse_args()
    if args.seconds <= 0:
        ap.error("--seconds must be > 0")

    repo = args.repo.resolve()
    if not (repo / "fuzz" / "Cargo.toml").is_file():
        print(f"error: {repo}/fuzz is not a cargo-fuzz layout", file=sys.stderr)
        return 1

    corpus_dir = args.results_dir / "corpus" / args.target
    logs_dir = args.results_dir / "logs"
    artifacts_dest = args.results_dir / "artifacts"
    for d in (corpus_dir, logs_dir, artifacts_dest):
        d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = logs_dir / f"{args.target}-{stamp}.log"

    cmd, out, rc, started = run_fuzz(args.target, args.seconds, repo, corpus_dir)
    log_path.write_text(f"$ {' '.join(cmd)}  (cwd={repo})\n\n{out}")

    artifacts = collect_artifacts(repo / "fuzz" / "artifacts", started, artifacts_dest, args.target)
    if rc == 0:
        status = "clean"
    elif artifacts:
        status = "crash"  # libFuzzer saved a finding artifact and exited nonzero
    else:
        status = "error"  # build failure, harness error, or wrapper timeout

    row = {
        "ts": utc_ts(),
        "target": args.target,
        "seconds": args.seconds,
        "status": status,
        "rc": rc,
        "duration_s": round(time.time() - started, 1),
        "cmd": cmd,
        "artifacts": artifacts,
        "corpus_units": len(list(corpus_dir.iterdir())),
        "log": str(log_path),
        "output_tail": out[-4000:],
    }
    append_jsonl(args.results_dir / "runs.jsonl", row)

    print(f"{args.target}: {status} (rc={rc}, {row['duration_s']}s, "
          f"corpus={row['corpus_units']}, artifacts={len(artifacts)})")
    print(f"row: {args.results_dir / 'runs.jsonl'}  log: {log_path}")
    return {"clean": 0, "crash": 3}.get(status, 1)


if __name__ == "__main__":
    sys.exit(main())
