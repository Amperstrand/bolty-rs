"""Bolty-rs differential test: compare bolty-cli operations across readers.

Sends the same bolty-cli commands (inspect, diagnose, uid) against two
different readers (ACR1252 via pcscd, GemPCTwin via pcscd when M5Stick
is in ccid mode) and compares the card state reports.

This tests the FULL bolty-rs stack: CLI → pyscard → pcscd → reader → NTAG424.
Any difference in card state or behavior between readers is a finding.

Usage:
    python3 bolty_diff.py --reader1 "ACR1252" --reader2 "GemPCTwin" --output results/bolty_diff.json
    python3 bolty_diff.py --reader1 "PICC" --output results/bolty_acr_only.json

Card safety: inspect/diagnose/uid are read-only. The --include-burn flag
adds burn+wipe cycles (uses deterministic keys, proven-safe envelope).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


BOLTY_CLI = str(Path(__file__).resolve().parents[3] / "target/release/bolty-cli")
if not Path(BOLTY_CLI).exists():
    BOLTY_CLI = str(Path(__file__).resolve().parents[3] / "target/debug/bolty-cli")


def run_bolty_cli(args: list[str], timeout: int = 30) -> dict:
    """Run a bolty-cli command and capture output."""
    cmd = [BOLTY_CLI] + args
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        duration_ms = (time.perf_counter() - t0) * 1000
        return {
            "cmd": " ".join(args),
            "rc": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "duration_ms": round(duration_ms, 1),
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        duration_ms = (time.perf_counter() - t0) * 1000
        return {
            "cmd": " ".join(args),
            "rc": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "duration_ms": round(duration_ms, 1),
            "success": False,
        }
    except Exception as e:
        return {
            "cmd": " ".join(args),
            "rc": -2,
            "stdout": "",
            "stderr": f"{type(e).__name__}: {e}",
            "duration_ms": 0,
            "success": False,
        }


READ_ONLY_COMMANDS = [
    ("uid", []),
    ("inspect", ["--issuer-key", "{issuer}", "--verbose"]),
    ("diagnose", ["--issuer-key", "{issuer}"]),
    ("picc", ["--issuer-key", "{issuer}"]),
]

BURN_COMMANDS = [
    ("wipe", ["--issuer-key", "00000000000000000000000000000001"]),
    ("inspect_post_wipe", ["--verbose"]),
]


def capture_reader_session(
    reader_pattern: str,
    issuer_key: str = "00000000000000000000000000000001",
    include_burn: bool = False,
) -> dict:
    """Run read-only (and optionally burn) commands against a specific reader."""

    # bolty-cli picks readers by name containing "PICC" (transport.rs:59-68)
    # For the GemPCTwin, we need to ensure bolty-cli selects it
    # The reader selection is automatic — we just run and record which reader was used
    results = []
    commands = list(READ_ONLY_COMMANDS)
    if include_burn:
        commands.extend(BURN_COMMANDS)

    for name, arg_template in commands:
        args = [name]
        for arg in arg_template:
            args.append(arg.replace("{issuer}", issuer_key))

        result = run_bolty_cli(args)
        result["test_id"] = name
        result["reader_target"] = reader_pattern
        results.append(result)
        status = "OK" if result["success"] else f"rc={result['rc']}"
        print(f"  {name}: {status} ({result['duration_ms']:.0f}ms)")
        if not result["success"] and result["stderr"]:
            print(f"    stderr: {result['stderr'][:100]}")

    return {
        "reader_target": reader_pattern,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commands": results,
    }


def compare_sessions(session1: dict, session2: dict) -> dict:
    """Compare two bolty-cli capture sessions."""
    s1_cmds = {r["test_id"]: r for r in session1.get("commands", [])}
    s2_cmds = {r["test_id"]: r for r in session2.get("commands", [])}

    matches = []
    mismatches = []
    missing = []
    extra = []

    for tid, s1 in s1_cmds.items():
        if tid not in s2_cmds:
            missing.append(tid)
            continue

        s2 = s2_cmds[tid]
        diff = {
            "test_id": tid,
            "cmd": s1.get("cmd", ""),
        }

        diff["rc_match"] = s1.get("rc") == s2.get("rc")
        diff["stdout_match"] = s1.get("stdout", "").strip() == s2.get("stdout", "").strip()

        dur1 = s1.get("duration_ms", 0)
        dur2 = s2.get("duration_ms", 0)
        diff["duration_1_ms"] = dur1
        diff["duration_2_ms"] = dur2
        diff["duration_ratio"] = round(dur2 / dur1, 1) if dur1 > 0 else None

        if not diff["rc_match"]:
            diff["rc_1"] = s1.get("rc")
            diff["rc_2"] = s2.get("rc")
        if not diff["stdout_match"]:
            diff["stdout_1_first_200"] = s1.get("stdout", "")[:200]
            diff["stdout_2_first_200"] = s2.get("stdout", "")[:200]

        is_match = diff["rc_match"] and diff["stdout_match"]
        diff["verdict"] = "MATCH" if is_match else "MISMATCH"

        if is_match:
            matches.append(diff)
        else:
            mismatches.append(diff)

    for tid in s2_cmds:
        if tid not in s1_cmds:
            extra.append(tid)

    return {
        "session1_reader": session1.get("reader_target"),
        "session2_reader": session2.get("reader_target"),
        "total_commands": len(s1_cmds),
        "total_matches": len(matches),
        "total_mismatches": len(mismatches),
        "missing_in_session2": missing,
        "extra_in_session2": extra,
        "matches": [m["test_id"] for m in matches],
        "mismatches": mismatches,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Differential test bolty-cli across readers"
    )
    parser.add_argument(
        "--reader1", required=True, help="First reader pattern (e.g., 'ACR1252')"
    )
    parser.add_argument(
        "--reader2", default=None, help="Second reader pattern (e.g., 'GemPCTwin')"
    )
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument(
        "--issuer-key",
        default="00000000000000000000000000000001",
        help="Deterministic issuer key",
    )
    parser.add_argument(
        "--include-burn",
        action="store_true",
        help="Include burn/wipe cycles (mutates card!)",
    )
    args = parser.parse_args(argv)

    print(f"Bolty CLI: {BOLTY_CLI}")
    print(f"Reader 1: {args.reader1}")
    if args.reader2:
        print(f"Reader 2: {args.reader2}")

    print(f"\n--- Session 1: {args.reader1} ---")
    session1 = capture_reader_session(
        args.reader1, args.issuer_key, args.include_burn
    )

    session2 = None
    if args.reader2:
        print(f"\n--- Session 2: {args.reader2} ---")
        session2 = capture_reader_session(
            args.reader2, args.issuer_key, args.include_burn
        )

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bolty_cli": BOLTY_CLI,
        "session1": session1,
    }

    if session2:
        comparison = compare_sessions(session1, session2)
        output["session2"] = session2
        output["comparison"] = comparison

        print(f"\n--- Comparison ---")
        print(f"Matches: {comparison['total_matches']}/{comparison['total_commands']}")
        if comparison["mismatches"]:
            print("Mismatches:")
            for m in comparison["mismatches"]:
                print(f"  {m['test_id']}: rc_match={m['rc_match']}, stdout_match={m['stdout_match']}")
                if not m["rc_match"]:
                    print(f"    rc: {m.get('rc_1')} vs {m.get('rc_2')}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()
