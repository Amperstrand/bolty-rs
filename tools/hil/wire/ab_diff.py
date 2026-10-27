#!/usr/bin/env python3
"""ab_diff.py — structural A/B diff of two wire-tap JSONL captures.

Compares command SEQUENCES and response CLASSES between captures (e.g.
real NTAG424 silicon vs the fixed jcardsim applet). Randomized crypto
material is masked via fingerprints (see wire_tap.py). Output: aligned
table + divergence report.

Usage: ab_diff.py A.wire.jsonl B.wire.jsonl [--label-a X --label-b Y]
"""
import argparse
import json
import sys


def load(path):
    return [json.loads(l) for l in open(path)]


def key(e):
    return (e["cmd"], e["resp_class"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--label-a", default="A")
    ap.add_argument("--label-b", default="B")
    args = ap.parse_args()

    A, B = load(args.a), load(args.b)
    # align by sequence of (cmd, resp_class); classic LCS
    n, m = len(A), len(B)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if key(A[i]) == key(B[j]) \
                else max(dp[i + 1][j], dp[i][j + 1])
    common = dp[0][0]
    print(f"{args.label_a}: {n} exchanges   {args.label_b}: {m} exchanges   "
          f"aligned: {common} ({common * 100 // max(n, 1)}% of {args.label_a})")
    print(f"{'seq':>5}  {'cmd':<18} {'A->sw':<8} {'B->sw':<8}  verdict")
    i = j = 0
    divergences = 0
    while i < n or j < m:
        if i < n and j < m and key(A[i]) == key(B[j]):
            verdict = "="
            ai, bj = A[i], B[j]
            print(f"{i:>5}  {ai['cmd']:<18} {ai['resp_sw']:<8} {bj['resp_sw']:<8}  {verdict}")
            i += 1
            j += 1
            continue
        # A-only or B-only at this point: pick the branch that realigns
        take_a = i < n and (j >= m or dp[i + 1][j] >= dp[i][j + 1])
        if take_a:
            print(f"{i:>5}  {A[i]['cmd']:<18} {A[i]['resp_sw']:<8} {'-':<8}  ONLY-{args.label_a}")
            i += 1
        else:
            print(f"{j:>5}  {B[j]['cmd']:<18} {'-':<8} {B[j]['resp_sw']:<8}  ONLY-{args.label_b}")
            j += 1
        divergences += 1
    print(f"\ndivergent slots: {divergences}")
    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main())
