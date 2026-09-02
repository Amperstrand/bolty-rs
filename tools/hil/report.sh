#!/usr/bin/env bash
# Allure report generation with history preservation (#75): the previous
# report's history/ is carried into the latest run's results dir before
# `allure generate`, so trend and retry views accumulate across runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ALLURE="$ROOT/tools/hil/results/allure"
REPORT="$ROOT/tools/hil/results/allure-report"

latest="$(ls -1 "$ALLURE" 2>/dev/null | sort | tail -1)"
if [ -z "$latest" ]; then
    echo "no allure results under $ALLURE — run 'make test-hil' first" >&2
    exit 1
fi

if [ -d "$REPORT/history" ]; then
    cp -r "$REPORT/history" "$ALLURE/$latest/"
fi

allure generate "$ALLURE/$latest" -o "$REPORT" --clean >/dev/null
echo "allure report: $REPORT/index.html (run: $latest)"
