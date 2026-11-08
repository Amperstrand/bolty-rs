#!/usr/bin/env bash
# soak-workspace.sh — the #272 flake-capture harness.
#
# The bolty-cli bin suite (94-test target) failed transiently TWICE
# under `cargo test --workspace --exclude bolty-esp32` (bench sessions
# 2026-10-27/28), 93/1 then 94/94 on immediate rerun — and the failing
# test NAME was never captured (log greps missed it before the rerun).
# Non-reproducing flakes get caught by soaking WITH capture, not by
# guessing: every iteration's full output is kept; the first failure
# prints the failing test block and exits 1.
#
# Usage: tools/soak-workspace.sh [ITERATIONS] [OUTDIR]
#   ITERATIONS  default 100; OUTDIR default /tmp/bolty-flake-soak
# Exit 0 = clean soak; 1 = reproduced (see OUTDIR/run-<n>.log);
# 2 = setup failure.
set -u
HERE="$(cd "$(dirname "$0")" && pwd -P)"
REPO="$(cd "$HERE/.." && pwd -P)"

N="${1:-100}"
OUT="${2:-/tmp/bolty-flake-soak}"
mkdir -p "$OUT"
cd "$REPO"

# per-worktree target dir (lesson B35: the global redirect makes
# worktree-local binaries a myth — pin it or soak the wrong artifacts)
export CARGO_TARGET_DIR="$REPO/target"

echo "soak: $N workspace iterations, logs in $OUT"
for i in $(seq 1 "$N"); do
  cargo test --workspace --exclude bolty-esp32 > "$OUT/run-$i.log" 2>&1
  RC=$?
  if [ "$RC" != "0" ]; then
    echo "FLAKE-REPRODUCED: iteration $i (rc=$RC)"
    echo "--- failing test blocks ---"
    grep -B2 -A12 'FAILED\|panicked at' "$OUT/run-$i.log" | head -40
    echo "full log: $OUT/run-$i.log"
    exit 1
  fi
  # keep only the last clean log (space) unless BOLTY_SOAK_KEEP_ALL
  [ -n "${BOLTY_SOAK_KEEP_ALL:-}" ] || { [ "$i" -gt 1 ] && rm -f "$OUT/run-$((i-1)).log"; }
  sleep "${BOLTY_SOAK_SLEEP:-2}"
done
echo "SOAK-CLEAN: $N iterations, 0 failures"
exit 0
