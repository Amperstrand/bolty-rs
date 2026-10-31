"""E2E test orchestrator: runs the full differential + bolty-rs test suite.

Usage:
    python3 e2e.py --phase apdu          # APDU differential (ccid vs ACR1252)
    python3 e2e.py --phase apdu --quick  # Quick: gem capture + diff only
    python3 e2e.py --phase bolty-acr     # bolty-cli against ACR1252 only
    python3 e2e.py --phase bolty-diff    # bolty-cli against both readers
    python3 e2e.py --phase all           # Everything (requires ccid mode switch)

Host-aware mode (#216 — the readers left ai-legion; the ACR1252 lives on
ai-legion-small as labgrid place ref-acr1252-small). Set:

    BOLTY_DIFFTEST_HOST=ai-legion-small   # ssh target owning pcscd + readers
    BOLTY_DIFFTEST_REMOTE_DIR=<path>      # difftest dir there (default
                                          # ~/src/bolty-rs-acr-h1/tools/hil/difftest)

and every reader-touching command (reader inventory, capture.py, bolty_diff.py)
runs remotely via ssh; result JSONs are fetched back into local results/.
File-only phases (diff.py, unit tests) always run locally. Without the env
vars nothing changes — local execution, byte for byte.

Role-switching phases (switch-ccid / switch-bolty / all) are OWNER-GATED
(#178): they reflash the M5Stick and put nucula/wallet state at risk.
Interactive runs get a confirmation prompt; scripts pass --yes or set
BOLTY_DIFFTEST_YES=1. Anything else is refused — fail closed.

Each phase produces results in results/ and prints a summary.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

SSH_HOST = os.environ.get("BOLTY_DIFFTEST_HOST", "").strip() or None
REMOTE_DIR = os.environ.get(
    "BOLTY_DIFFTEST_REMOTE_DIR", "~/src/bolty-rs-acr-h1/tools/hil/difftest"
).strip()
REMOTE_TMP = "/tmp/bolty-difftest-remote"


_remote_home_cache: str | None = None


def _remote_home() -> str:
    """Remote $HOME (cached; '' if unresolvable — the run then fails loudly
    at cd, which is the honest outcome)."""
    global _remote_home_cache
    if _remote_home_cache is None:
        _remote_home_cache = ""
        try:
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                 SSH_HOST, "echo $HOME"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                _remote_home_cache = r.stdout.strip().splitlines()[-1]
        except Exception:
            pass
    return _remote_home_cache


def _remote_dir_abs() -> str:
    """REMOTE_DIR as an absolute remote path. shlex.quote freezes a literal
    tilde mid-command, so ~/ forms are resolved against the remote $HOME."""
    if REMOTE_DIR.startswith("~/") and SSH_HOST:
        home = _remote_home()
        if home:
            return home + REMOTE_DIR[1:]
    return REMOTE_DIR

sys.path.insert(0, str(HERE.parent))  # hil package (tools/hil/hil)

from hil.labgrid_state import note_rig_state  # noqa: E402


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


def run_reader_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    output: Path | None = None,
) -> tuple[int, str, Path | None]:
    """Run a reader-touching command.

    Local mode: plain run(); `output` (if any) is produced at its own path
    by the tool itself.

    Host mode (BOLTY_DIFFTEST_HOST): executes via non-interactive ssh in
    REMOTE_DIR. An `output` path argument is rewritten to a remote scratch
    file, fetched back after the run, and returned as the effective local
    result path. Caller-independent: local callers see the same contract.
    """
    if not SSH_HOST:
        rc, out = run(cmd, cwd=cwd, timeout=timeout)
        return rc, out, output if (output and output.exists()) else None

    remote_cmd = list(cmd)
    remote_out: str | None = None
    if output is not None:
        # rewrite the --output argument to a remote scratch path
        remote_out = f"{REMOTE_TMP}/{output.name}"
        remote_cmd = [
            remote_out if a == str(output) else a for a in remote_cmd
        ]
    # map local difftest paths onto the remote checkout (capture.py,
    # bolty_diff.py, ... are executed from the remote difftest dir)
    rdir = _remote_dir_abs()
    remote_cmd = [a.replace(f"{HERE}/", f"{rdir}/") for a in remote_cmd]
    shell = (f"mkdir -p {shlex.quote(REMOTE_TMP)} && "
             f"cd {shlex.quote(rdir)} && {shlex.join(remote_cmd)}")
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
             SSH_HOST, shell],
            capture_output=True, text=True, timeout=timeout,
        )
        rc, out = r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return -1, f"TIMEOUT after {timeout}s (ssh {SSH_HOST})", None

    fetched: Path | None = None
    if remote_out is not None and rc == 0:
        fr = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
             SSH_HOST, f"cat {shlex.quote(remote_out)}"],
            capture_output=True, timeout=60,
        )
        if fr.returncode == 0 and fr.stdout:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(fr.stdout)
            fetched = output
        else:
            rc, out = -3, f"remote output fetch failed for {remote_out}: {fr.stderr[-200:]!r}"
    return rc, out, fetched


def reader_inventory() -> list[str]:
    """List pcsc reader names — remotely when host mode is active."""
    probe = ["python3", "-c",
             "import json; from smartcard.System import readers; "
             "print(json.dumps([str(r) for r in readers()]))"]
    rc, out, _ = run_reader_cmd(probe, cwd=HERE, timeout=60)
    if rc != 0:
        return []
    line = next((l for l in out.splitlines() if l.startswith("[")), "")
    try:
        return json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return []


def phase_apdu(golden_path: Path | None = None, quick: bool = False,
               acr_only: bool = False) -> dict:
    """Phase 1: APDU differential testing against ACR1252 golden reference.

    quick=True skips the ACR golden re-capture (the committed golden is the
    reference) and the fuzz category, and trims repeat sleeps — gem capture +
    diff only (#74).

    acr_only=True runs the ACR-self-consistency variant: capture from the
    ACR1252 (quick-trimmed) and diff against the committed golden WITHOUT
    requiring the GemPCTwin reader. This is the stick-free sanity path for
    pin-bump/dependency changes (#95-class validations, t_8a294110): the
    M5Stick stays in whatever role it runs, and the answer is "does the ACR
    path still reproduce the recorded golden behavior".
    """
    mode = " [QUICK]" if quick else (" [ACR-ONLY]" if acr_only else "")
    print("=" * 60)
    print(f"PHASE: APDU Differential Testing{mode}")
    print("=" * 60)
    t0 = time.perf_counter()

    if golden_path is None:
        golden_path = RESULTS / "golden_acr1252.json"

    if not golden_path.exists():
        print(f"ERROR: golden reference not found: {golden_path}")
        return {"phase": "apdu", "status": "SKIP", "reason": "no golden"}

    if SSH_HOST:
        print(f"HOST MODE: reader phases via ssh {SSH_HOST} ({REMOTE_DIR})")

    readers = reader_inventory()
    has_gem = any("GemPCTwin" in r for r in readers)
    has_acr = any("ACR1252" in r for r in readers)

    print(f"Readers: GemPCTwin={'yes' if has_gem else 'no'}, ACR1252={'yes' if has_acr else 'no'}")

    results = {"phase": "apdu", "timestamp": datetime.now(timezone.utc).isoformat(),
               "quick": quick, "acr_only": acr_only}
    if SSH_HOST:
        results["host"] = SSH_HOST

    # Capture from ACR1252 (always available; sanity check vs committed golden)
    if has_acr and (acr_only or not quick):
        acr_out = RESULTS / "e2e_acr_capture.json"
        acr_cmd = ["python3", str(HERE / "capture.py"), "--reader", "PICC",
                   "--output", str(acr_out)]
        if quick or acr_only:
            acr_cmd += ["--no-fuzz", "--repeat-sleep", "0.02"]
        print(f"\n--- Capturing from ACR1252{' (no fuzz, 0.02s repeat sleep)' if (quick or acr_only) else ''} ---")
        rc, out, got = run_reader_cmd(acr_cmd, output=acr_out)
        if rc == 0 and got:
            print(f"  Saved: {acr_out}")
            results["acr_capture"] = str(acr_out)
        else:
            print(f"  FAILED: {out[:200]}")
            results["acr_capture_error"] = out[:200]
    elif quick:
        print("\n--- Quick mode: skipping ACR re-capture (committed golden is the reference) ---")

    # Capture from GemPCTwin (requires ccid mode) — skipped entirely in
    # acr_only: the whole point is a stick-free run.
    if has_gem and not acr_only:
        gem_out = RESULTS / "e2e_gem_capture.json"
        gem_cmd = ["python3", str(HERE / "capture.py"), "--reader", "GemPCTwin",
                   "--output", str(gem_out)]
        if quick:
            gem_cmd += ["--no-fuzz", "--repeat-sleep", "0.02"]
        print(f"\n--- Capturing from GemPCTwin{' (no fuzz, 0.02s repeat sleep)' if quick else ''} ---")
        rc, out, got = run_reader_cmd(gem_cmd, output=gem_out)
        if rc == 0 and got:
            print(f"  Saved: {gem_out}")
            results["gem_capture"] = str(gem_out)

            # Diff against golden
            print(f"\n--- Diffing GemPCTwin vs golden ---")
            diff_out = RESULTS / "e2e_diff.json"
            diff_cmd = [
                "python3", str(HERE / "diff.py"),
                "--golden", str(golden_path),
                "--test", str(gem_out),
                "--output", str(diff_out),
            ]
            if quick:
                diff_cmd.append("--skip-fuzz")
            rc, out = run(diff_cmd)
            print(out)

            if diff_out.exists():
                d = json.loads(diff_out.read_text())
                results["diff"] = {
                    "matches": d["total_matches"],
                    "mismatches": d["total_mismatches"],
                    "total": d["total_golden"],
                    "cards_match": d["cards_match"],
                }
    elif not acr_only:
        print("\nGemPCTwin not visible (M5Stick not in ccid mode)")
        print("Run: python3 e2e.py --phase switch-ccid first")

    # Diff ACR capture vs golden too (sanity check)
    if has_acr and (acr_only or not quick) and "acr_capture" in results:
        acr_diff_out = RESULTS / "e2e_acr_vs_golden.json"
        diff_cmd = [
            "python3", str(HERE / "diff.py"),
            "--golden", str(golden_path),
            "--test", str(results["acr_capture"]),
            "--output", str(acr_diff_out),
        ]
        if acr_only:
            diff_cmd.append("--skip-fuzz")
        rc, out = run(diff_cmd)
        if acr_only:
            print(out)
        if acr_diff_out.exists():
            d = json.loads(acr_diff_out.read_text())
            results["acr_vs_golden"] = {
                "matches": d["total_matches"],
                "mismatches": d["total_mismatches"],
                "total": d["total_golden"],
            }

    elapsed = time.perf_counter() - t0
    results["elapsed_s"] = round(elapsed, 1)
    if acr_only:
        # The ACR-vs-golden diff IS the run's verdict (no gem diff happened).
        results["status"] = "PASS" if results.get("acr_vs_golden", {}).get("mismatches", 99) == 0 else "FINDINGS"
        mode_label = "acr-only"
    else:
        results["status"] = "PASS" if results.get("diff", {}).get("mismatches", 99) == 0 else "FINDINGS"
        mode_label = "quick" if quick else "full"
    print(f"\nElapsed: {elapsed:.1f}s ({mode_label} mode)")
    return results


def phase_bolty_acr() -> dict:
    """Phase 2: bolty-cli against ACR1252 only."""
    print("=" * 60)
    print("PHASE: bolty-cli against ACR1252")
    print("=" * 60)
    if SSH_HOST:
        print(f"HOST MODE: reader phases via ssh {SSH_HOST} ({REMOTE_DIR})")

    out_path = RESULTS / "e2e_bolty_acr.json"
    rc, out, got = run_reader_cmd([
        "python3", str(HERE / "bolty_diff.py"),
        "--reader1", "PICC",
        "--output", str(out_path),
    ], timeout=180, output=out_path)

    # `got` is the freshly-produced result (None on failure — a stale
    # committed results/e2e_bolty_acr.json must never read as PASS)
    if got:
        d = json.loads(got.read_text())
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
    readers = reader_inventory()
    if not any("GemPCTwin" in r for r in readers):
        print("GemPCTwin not visible — skipping (need ccid mode)")
        return {"phase": "bolty-diff", "status": "SKIP", "reason": "no GemPCTwin"}

    out_path = RESULTS / "e2e_bolty_diff.json"
    rc, out, got = run_reader_cmd([
        "python3", str(HERE / "bolty_diff.py"),
        "--reader1", "PICC",
        "--reader2", "GemPCTwin",
        "--output", str(out_path),
    ], timeout=300, output=out_path)

    # `got` is the freshly-produced result (None on failure — a stale
    # committed results/e2e_bolty_diff.json must never read as PASS)
    if got:
        d = json.loads(got.read_text())
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


ROLE_SWITCH_RISK = (
    "Role-switching REFLASHES the M5Stick (prebuilt merged image via "
    "role_switch.py) — any nucula/wallet state on the stick is at risk. "
    "AGENTS.md: no reflash/role-switch without an explicit owner decision."
)

ROLE_SWITCH_CONFIRM_WORD = "switch"


def owner_approved_role_switch(assume_yes=False, stdin=None, env=None):
    """Owner-approval gate for M5Stick role-switching (issue #178).

    Fail-closed: approved only via --yes, BOLTY_DIFFTEST_YES != 0/empty,
    or an interactive terminal where the operator types the confirmation
    word after reading the risk statement. Everything else — non-tty
    stdin (CI, cron, piped), EOF, wrong word — refuses.
    """
    env = os.environ if env is None else env
    if assume_yes:
        return True
    if env.get("BOLTY_DIFFTEST_YES", "").strip() not in ("", "0"):
        return True
    stdin = stdin if stdin is not None else sys.stdin
    try:
        if not stdin.isatty():
            return False
    except Exception:  # noqa: BLE001 — a weird stdin object is not approval
        return False
    print(f"\n{ROLE_SWITCH_RISK}")
    print(f"Type '{ROLE_SWITCH_CONFIRM_WORD}' to proceed: ", end="",
          flush=True)
    try:
        answer = stdin.readline().strip()
    except Exception:  # noqa: BLE001 — a broken stdin is not approval
        return False
    return answer == ROLE_SWITCH_CONFIRM_WORD


def phase_switch(target: str, assume_yes: bool = False) -> dict:
    """Switch M5Stick role (bolty ↔ ccid) — owner-gated (#178)."""
    if not owner_approved_role_switch(assume_yes=assume_yes):
        print(f"REFUSED: role switch to {target} needs owner approval "
              f"(--yes or BOLTY_DIFFTEST_YES=1; interactive runs get a "
              f"prompt). {ROLE_SWITCH_RISK}")
        return {"phase": f"switch-{target}", "status": "REFUSED",
                "output": "owner approval required"}
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
    from tollgate_lab import ensure_run_headroom

    hygiene = ensure_run_headroom()
    if hygiene.acted:
        print(f"disk hygiene: {hygiene.actions}")

    parser = argparse.ArgumentParser(description="E2E test orchestrator")
    parser.add_argument("--phase", required=True,
                        choices=["apdu", "bolty-acr", "bolty-diff", "unit-tests",
                                 "switch-ccid", "switch-bolty", "all"],
                        help="Which phase to run")
    parser.add_argument("--golden", default=None, help="Path to golden reference JSON")
    parser.add_argument("--quick", action="store_true",
                        help="APDU phase: gem capture + diff only (skip ACR re-capture, "
                             "skip fuzz, 0.02s repeat sleeps)")
    parser.add_argument("--acr-only", action="store_true",
                        help="APDU phase: ACR capture + diff vs committed golden only — "
                             "no GemPCTwin required (stick-free sanity path, e.g. after "
                             "dependency pin bumps)")
    parser.add_argument("--yes", action="store_true",
                        help="Pre-approve the M5Stick role switches (#178 owner gate): "
                             "skips the interactive confirmation. Non-interactive runs "
                             "without this (or BOLTY_DIFFTEST_YES=1) are REFUSED.")
    args = parser.parse_args(argv)

    note_rig_state(test=f"difftest:{args.phase}")

    golden = Path(args.golden) if args.golden else None
    all_results = []

    if args.phase == "all":
        # Full sequence
        all_results.append(phase_unit_tests())
        all_results.append(phase_bolty_acr())
        all_results.append(phase_switch("ccid", assume_yes=args.yes))
        if all_results[-1].get("status") == "REFUSED":
            # Without the ccid role the APDU/bolty-diff phases have no
            # GemPCTwin reader — abort the sequence instead of failing
            # them noisily for the wrong reason.
            print("\nRole switch refused — aborting the remaining phases.")
        else:
            all_results.append(phase_apdu(golden))
            all_results.append(phase_bolty_diff())
            all_results.append(phase_switch("bolty", assume_yes=args.yes))
    elif args.phase.startswith("switch-"):
        target = args.phase.split("-", 1)[1]
        all_results.append(phase_switch(target, assume_yes=args.yes))
    else:
        func = {
            "apdu": lambda: phase_apdu(golden, quick=args.quick,
                                       acr_only=args.acr_only),
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
