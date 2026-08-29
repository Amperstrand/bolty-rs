"""E2E test orchestrator: runs the full differential + bolty-rs test suite.

Usage:
    python3 e2e.py --phase apdu          # APDU differential (ccid vs ACR1252)
    python3 e2e.py --phase bolty-acr     # bolty-cli against ACR1252 only
    python3 e2e.py --phase bolty-diff    # bolty-cli against both readers
    python3 e2e.py --phase all           # Everything (requires ccid mode switch)

Each phase produces results in results/ and prints a summary.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 120) -> tuple[int, str]:
    """Run a command, return (rc, output)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return -1, f"TIMEOUT after {timeout}s"
    except Exception as e:
        return -2, f"{type(e).__name__}: {e}"


def phase_apdu(golden_path: Path | None = None) -> dict:
    """Phase 1: APDU differential testing against ACR1252 golden reference."""
    print("=" * 60)
    print("PHASE: APDU Differential Testing")
    print("=" * 60)

    if golden_path is None:
        golden_path = RESULTS / "golden_acr1252.json"

    if not golden_path.exists():
        print(f"ERROR: golden reference not found: {golden_path}")
        return {"phase": "apdu", "status": "SKIP", "reason": "no golden"}

    # Check if GemPCTwin is available (ccid mode)
    rc, out = run([
        "python3", "-c",
        "from smartcard.System import readers; print([str(r) for r in readers()])"
    ])
    has_gem = "GemPCTwin" in out
    has_acr = "ACR1252" in out

    print(f"Readers: GemPCTwin={'yes' if has_gem else 'no'}, ACR1252={'yes' if has_acr else 'no'}")

    results = {"phase": "apdu", "timestamp": datetime.now(timezone.utc).isoformat()}

    # Capture from ACR1252 (always available)
    if has_acr:
        acr_out = RESULTS / "e2e_acr_capture.json"
        print(f"\n--- Capturing from ACR1252 ---")
        rc, out = run(["python3", str(HERE / "capture.py"), "--reader", "PICC", "--output", str(acr_out)])
        if rc == 0:
            print(f"  Saved: {acr_out}")
            results["acr_capture"] = str(acr_out)
        else:
            print(f"  FAILED: {out[:200]}")
            results["acr_capture_error"] = out[:200]

    # Capture from GemPCTwin (requires ccid mode)
    if has_gem:
        gem_out = RESULTS / "e2e_gem_capture.json"
        print(f"\n--- Capturing from GemPCTwin ---")
        rc, out = run(["python3", str(HERE / "capture.py"), "--reader", "GemPCTwin", "--output", str(gem_out)])
        if rc == 0:
            print(f"  Saved: {gem_out}")
            results["gem_capture"] = str(gem_out)

            # Diff against golden
            print(f"\n--- Diffing GemPCTwin vs golden ---")
            diff_out = RESULTS / "e2e_diff.json"
            rc, out = run([
                "python3", str(HERE / "diff.py"),
                "--golden", str(golden_path),
                "--test", str(gem_out),
                "--output", str(diff_out),
            ])
            print(out)

            if diff_out.exists():
                d = json.loads(diff_out.read_text())
                results["diff"] = {
                    "matches": d["total_matches"],
                    "mismatches": d["total_mismatches"],
                    "total": d["total_golden"],
                    "cards_match": d["cards_match"],
                }
    else:
        print("\nGemPCTwin not visible (M5Stick not in ccid mode)")
        print("Run: python3 e2e.py --phase switch-ccid first")

    # Diff ACR capture vs golden too (sanity check)
    if has_acr and "acr_capture" in results:
        acr_diff_out = RESULTS / "e2e_acr_vs_golden.json"
        rc, out = run([
            "python3", str(HERE / "diff.py"),
            "--golden", str(golden_path),
            "--test", str(results["acr_capture"]),
            "--output", str(acr_diff_out),
        ])
        if acr_diff_out.exists():
            d = json.loads(acr_diff_out.read_text())
            results["acr_vs_golden"] = {
                "matches": d["total_matches"],
                "mismatches": d["total_mismatches"],
                "total": d["total_golden"],
            }

    results["status"] = "PASS" if results.get("diff", {}).get("mismatches", 99) == 0 else "FINDINGS"
    return results


def phase_bolty_acr() -> dict:
    """Phase 2: bolty-cli against ACR1252 only."""
    print("=" * 60)
    print("PHASE: bolty-cli against ACR1252")
    print("=" * 60)

    out_path = RESULTS / "e2e_bolty_acr.json"
    rc, out = run([
        "python3", str(HERE / "bolty_diff.py"),
        "--reader1", "PICC",
        "--output", str(out_path),
    ], timeout=180)

    if out_path.exists():
        d = json.loads(out_path.read_text())
        cmds = d.get("session1", {}).get("commands", [])
        ok = sum(1 for c in cmds if c.get("success"))
        print(f"\nbolty-cli on ACR1252: {ok}/{len(cmds)} commands OK")
        for c in cmds:
            status = "OK" if c["success"] else f"rc={c['rc']}"
            print(f"  {c['test_id']}: {status} ({c['duration_ms']:.0f}ms)")
        return {"phase": "bolty-acr", "status": "PASS" if ok >= 3 else "FINDINGS", "ok": ok, "total": len(cmds)}

    return {"phase": "bolty-acr", "status": "FAIL", "output": out[:200]}


def phase_bolty_diff() -> dict:
    """Phase 3: bolty-cli against both readers (differential)."""
    print("=" * 60)
    print("PHASE: bolty-cli differential (ACR1252 vs GemPCTwin)")
    print("=" * 60)

    # Check for GemPCTwin
    rc, out = run([
        "python3", "-c",
        "from smartcard.System import readers; print([str(r) for r in readers()])"
    ])
    if "GemPCTwin" not in out:
        print("GemPCTwin not visible — skipping (need ccid mode)")
        return {"phase": "bolty-diff", "status": "SKIP", "reason": "no GemPCTwin"}

    out_path = RESULTS / "e2e_bolty_diff.json"
    rc, out = run([
        "python3", str(HERE / "bolty_diff.py"),
        "--reader1", "PICC",
        "--reader2", "GemPCTwin",
        "--output", str(out_path),
    ], timeout=300)

    if out_path.exists():
        d = json.loads(out_path.read_text())
        comp = d.get("comparison", {})
        print(f"\nComparison: {comp.get('total_matches', 0)}/{comp.get('total_commands', 0)} match")
        if comp.get("mismatches"):
            for m in comp["mismatches"]:
                print(f"  MISMATCH {m['test_id']}: rc_match={m['rc_match']}")
        return {
            "phase": "bolty-diff",
            "status": "PASS" if comp.get("total_mismatches", 99) == 0 else "FINDINGS",
            **comp,
        }

    return {"phase": "bolty-diff", "status": "FAIL", "output": out[:200]}


def phase_unit_tests() -> dict:
    """Phase 4: Run unit tests (golden data + difftest tool)."""
    print("=" * 60)
    print("PHASE: Unit Tests")
    print("=" * 60)

    suites = [
        ("difftest tool", HERE / "tests" / "test_difftest.py"),
        ("golden responses", HERE / "generated" / "test_golden_responses.py"),
    ]

    results = {"phase": "unit-tests", "suites": {}}
    all_pass = True

    for name, test_path in suites:
        if not test_path.exists():
            results["suites"][name] = "SKIP (not found)"
            continue

        rc, out = run(
            ["python3", "-m", "pytest", str(test_path), "-q"],
            cwd=HERE,
            timeout=60,
        )
        passed = rc == 0
        results["suites"][name] = "PASS" if passed else f"FAIL ({out[-100:]})"
        if not passed:
            all_pass = False
        # Extract test count
        for line in out.split("\n"):
            if "passed" in line:
                print(f"  {name}: {line.strip()}")
                break

    results["status"] = "PASS" if all_pass else "FAIL"
    return results


def phase_switch(target: str) -> dict:
    """Switch M5Stick role (bolty ↔ ccid)."""
    print(f"Switching M5Stick to {target} role...")

    overnight_dir = HERE.parent / "overnight"
    rc, out = run([
        "python3", "-c",
        f"import sys; sys.path.insert(0, '.'); import role_switch; "
        f"r = role_switch.switch_to('{target}'); print(f'ok={{r.ok}} detail={{r.detail}}')"
    ], cwd=overnight_dir, timeout=300)

    print(f"  {out.strip()}")
    ok = "ok=True" in out
    return {"phase": f"switch-{target}", "status": "PASS" if ok else "FAIL", "output": out.strip()}


def main(argv=None):
    parser = argparse.ArgumentParser(description="E2E test orchestrator")
    parser.add_argument("--phase", required=True,
                        choices=["apdu", "bolty-acr", "bolty-diff", "unit-tests",
                                 "switch-ccid", "switch-bolty", "all"],
                        help="Which phase to run")
    parser.add_argument("--golden", default=None, help="Path to golden reference JSON")
    args = parser.parse_args(argv)

    golden = Path(args.golden) if args.golden else None
    all_results = []

    if args.phase == "all":
        # Full sequence
        all_results.append(phase_unit_tests())
        all_results.append(phase_bolty_acr())
        all_results.append(phase_switch("ccid"))
        all_results.append(phase_apdu(golden))
        all_results.append(phase_bolty_diff())
        all_results.append(phase_switch("bolty"))
    elif args.phase.startswith("switch-"):
        target = args.phase.split("-", 1)[1]
        all_results.append(phase_switch(target))
    else:
        func = {
            "apdu": lambda: phase_apdu(golden),
            "bolty-acr": phase_bolty_acr,
            "bolty-diff": phase_bolty_diff,
            "unit-tests": phase_unit_tests,
        }[args.phase]
        all_results.append(func())

    # Summary
    print("\n" + "=" * 60)
    print("E2E SUMMARY")
    print("=" * 60)
    for r in all_results:
        print(f"  {r.get('phase', '?'):20s}: {r.get('status', '?')}")

    # Save summary
    summary_path = RESULTS / "e2e_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(all_results, indent=2, default=str))
    print(f"\nSaved: {summary_path}")

    all_pass = all(r.get("status") in ("PASS", "SKIP") for r in all_results)
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
