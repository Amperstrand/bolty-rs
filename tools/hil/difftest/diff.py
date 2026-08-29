"""Diff tool: compare two capture sessions and report all differences.

Usage:
    python3 diff.py --golden golden_acr1252.json --test test_ccid.json
    python3 diff.py --golden golden.json --test test.json --output diff_report.json

Comparison modes (auto-selected per test):

  exact      — response bytes, SW, success must all match.
               Used for card-independent tests AND card-dependent tests
               when both captures used the SAME physical card.

  structural — SW, response length, success must match. Exact bytes NOT
               compared because different cards produce different content.
               Used for card-dependent tests when the two captures used
               DIFFERENT physical cards (detected by card UID mismatch).

Timing is always compared (flag if test > 2x golden).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apdu_matrix import get_test_by_id


def load_session(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"ERROR: {path} not found", file=sys.stderr)
        sys.exit(1)
    return json.loads(p.read_text())


def _diff_timing(g: dict, t: dict, diff: dict) -> None:
    g_dur = g.get("duration_ms", 0)
    t_dur = t.get("duration_ms", 0)
    diff["duration_golden_ms"] = g_dur
    diff["duration_test_ms"] = t_dur
    diff["duration_ratio"] = round(t_dur / g_dur, 1) if g_dur > 0 else None
    diff["duration_concern"] = g_dur > 0 and t_dur > 2 * g_dur


def _diff_sw(g: dict, t: dict, diff: dict) -> None:
    g_sw = g.get("sw", "")
    t_sw = t.get("sw", "")
    diff["sw_match"] = g_sw == t_sw
    if not diff["sw_match"]:
        diff["golden_sw"] = g_sw
        diff["test_sw"] = t_sw


def _diff_exact(g: dict, t: dict, diff: dict) -> bool:
    g_resp = g.get("response_bytes", "")
    t_resp = t.get("response_bytes", "")
    diff["response_match"] = g_resp == t_resp
    if not diff["response_match"]:
        diff["golden_response"] = g_resp
        diff["test_response"] = t_resp

    g_err = g.get("error")
    t_err = t.get("error")
    diff["error_match"] = (g_err is None) == (t_err is None)
    if not diff["error_match"]:
        diff["golden_error"] = g_err
        diff["test_error"] = t_err

    return diff["response_match"] and diff["sw_match"] and diff.get("error_match", True)


def _diff_structural(g: dict, t: dict, diff: dict) -> bool:
    g_resp = g.get("response_bytes", "")
    t_resp = t.get("response_bytes", "")
    diff["response_len_match"] = len(g_resp) == len(t_resp)
    diff["golden_response_len"] = len(g_resp)
    diff["test_response_len"] = len(t_resp)
    if not diff["response_len_match"]:
        diff["response_len_diff"] = len(t_resp) - len(g_resp)

    return diff["response_len_match"] and diff["sw_match"]


def diff_sessions(golden: dict, test: dict) -> dict:
    golden_results = {r["test_id"]: r for r in golden.get("results", [])}
    test_results = {r["test_id"]: r for r in test.get("results", [])}
    same_card = golden.get("card_uid") == test.get("card_uid")

    matches = []
    mismatches = []
    missing_in_test = []
    extra_in_test = []
    structural_count = 0

    for tid, g in golden_results.items():
        if tid not in test_results:
            missing_in_test.append(tid)
            continue

        t = test_results[tid]
        test_def = get_test_by_id(tid)
        card_dependent = test_def.card_dependent if test_def else g.get("card_dependent", False)

        use_structural = card_dependent and not same_card
        if use_structural:
            structural_count += 1

        diff = {
            "test_id": tid,
            "category": g.get("category", ""),
            "description": g.get("description", ""),
            "card_dependent": card_dependent,
            "comparison_mode": "structural" if use_structural else "exact",
        }

        diff["success_match"] = g.get("success") == t.get("success")
        _diff_sw(g, t, diff)
        _diff_timing(g, t, diff)

        if use_structural:
            is_match = _diff_structural(g, t, diff) and diff["success_match"]
        else:
            is_match = _diff_exact(g, t, diff) and diff["success_match"]

        diff["verdict"] = "MATCH" if is_match else "MISMATCH"

        if is_match:
            matches.append(diff)
        else:
            mismatches.append(diff)

    for tid in test_results:
        if tid not in golden_results:
            extra_in_test.append(tid)

    category_summary: dict[str, dict] = {}
    for m in matches + mismatches:
        cat = m["category"]
        if cat not in category_summary:
            category_summary[cat] = {"match": 0, "mismatch": 0}
        if m["verdict"] == "MATCH":
            category_summary[cat]["match"] += 1
        else:
            category_summary[cat]["mismatch"] += 1

    return {
        "golden_reader": golden.get("reader"),
        "test_reader": test.get("reader"),
        "golden_card": golden.get("card_uid"),
        "test_card": test.get("card_uid"),
        "cards_match": same_card,
        "comparison_note": (
            "Same card detected — exact byte comparison for all tests"
            if same_card
            else "Different cards — structural comparison for card-dependent tests (byte content not compared)"
        ),
        "total_golden": len(golden_results),
        "total_test": len(test_results),
        "total_matches": len(matches),
        "total_mismatches": len(mismatches),
        "total_structural": structural_count,
        "total_missing_in_test": len(missing_in_test),
        "total_extra_in_test": len(extra_in_test),
        "match_rate": f"{len(matches)}/{len(golden_results)}" if golden_results else "N/A",
        "category_summary": category_summary,
        "matches": [m["test_id"] for m in matches],
        "mismatches": mismatches,
        "missing_in_test": missing_in_test,
        "extra_in_test": extra_in_test,
    }


def format_report(diff: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("DIFFERENTIAL TEST REPORT")
    lines.append("=" * 70)
    lines.append(f"Golden: {diff['golden_reader']} (card: {diff['golden_card']})")
    lines.append(f"Test:   {diff['test_reader']} (card: {diff['test_card']})")
    lines.append(f"Cards match: {diff['cards_match']}")
    lines.append(f"Note: {diff['comparison_note']}")
    lines.append("")
    lines.append(f"Results: {diff['total_matches']} match / {diff['total_mismatches']} mismatch / "
                 f"{diff['total_missing_in_test']} missing / {diff['total_extra_in_test']} extra")
    lines.append(f"Match rate: {diff['match_rate']}")
    if diff["total_structural"]:
        lines.append(f"Structural comparisons (different cards): {diff['total_structural']} tests")
    lines.append("")

    if diff["category_summary"]:
        lines.append("By category:")
        for cat, counts in sorted(diff["category_summary"].items()):
            total = counts["match"] + counts["mismatch"]
            pct = counts["match"] / total * 100 if total > 0 else 0
            lines.append(f"  {cat:20s}: {counts['match']}/{total} ({pct:.0f}%)")
        lines.append("")

    if diff["mismatches"]:
        lines.append("MISMATCHES:")
        lines.append("-" * 70)
        for m in diff["mismatches"]:
            mode = m.get("comparison_mode", "exact")
            lines.append(f"  {m['test_id']} [{m['category']}] ({mode}): {m['description']}")

            if mode == "structural":
                if not m.get("response_len_match", True):
                    lines.append(f"    Length: golden={m.get('golden_response_len')} "
                                 f"vs test={m.get('test_response_len')} "
                                 f"(diff={m.get('response_len_diff', '?')})")
            else:
                if not m.get("response_match", True):
                    lines.append(f"    Response: golden={m.get('golden_response', '')} "
                                 f"vs test={m.get('test_response', '')}")

            if not m.get("sw_match", True):
                lines.append(f"    SW: golden={m.get('golden_sw', '')} "
                             f"vs test={m.get('test_sw', '')}")

            if not m.get("success_match", True):
                lines.append(f"    Success differs")

            if m.get("duration_concern"):
                lines.append(f"    Timing: golden={m['duration_golden_ms']}ms "
                             f"vs test={m['duration_test_ms']}ms "
                             f"({m['duration_ratio']}x slower)")

            if not m.get("error_match", True):
                lines.append(f"    Error: golden={m.get('golden_error')} "
                             f"vs test={m.get('test_error')}")

            lines.append("")

    if diff["missing_in_test"]:
        lines.append(f"MISSING IN TEST: {', '.join(diff['missing_in_test'])}")
    if diff["extra_in_test"]:
        lines.append(f"EXTRA IN TEST: {', '.join(diff['extra_in_test'])}")

    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare two APDU capture sessions")
    parser.add_argument("--golden", required=True, help="Golden reference JSON path")
    parser.add_argument("--test", required=True, help="Test session JSON path")
    parser.add_argument("--output", help="Optional output JSON for the diff report")
    args = parser.parse_args(argv)

    golden = load_session(args.golden)
    test = load_session(args.test)

    diff = diff_sessions(golden, test)
    report = format_report(diff)
    print(report)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(diff, indent=2))
        print(f"\nDiff report saved: {args.output}")


if __name__ == "__main__":
    main()
