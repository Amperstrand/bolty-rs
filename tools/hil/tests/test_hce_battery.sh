#!/bin/bash
# HCE boltcard test battery — run once the S20 is physically on the ACR antenna
# with the dev.boltcard.hce app in foreground (preferred HCE service).
#
# Prerequisites:
#   - S20 back-panel directly on ACR antenna (no metal between)
#   - dev.boltcard.hce/.MainActivity in foreground
#   - HCE card registered in cards.toml (PR #207)
#
# Keys (deterministic issuer 0000...0001 v1, UID 04996c6a926980):
#   K0: 2ac7a4cdbfc53878a807e30acc7f88ac
#   K1: 55da174c9608993dc27bb3f30a4a7314
#   K2: d864bf53286b53011f75301959a0faee

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CLI="${BOLTY_CLI:-$ROOT/target/debug/bolty-cli}"
READER="--reader ACR1252 Dual Reader PICC"
ISSUER=00000000000000000000000000000001
UID=04996c6a926980

pass=0; fail=0; skip=0

t() {  # t <name> <command...>
    local name="$1"; shift
    echo -n "  $name: "
    if "$@" >/dev/null 2>&1; then
        echo "PASS"; ((pass++))
    else
        echo "FAIL"; ((fail++))
    fi
}

echo "=== HCE boltcard test battery ($(date '+%H:%M:%S')) ==="
echo ""

echo "--- 1. Card detection ---"
echo -n "  uid: "
UID_OUT=$($CLI $READER uid 2>&1) || true
if echo "$UID_OUT" | grep -q "$UID"; then
    echo "PASS (uid=$UID)"; ((pass++))
elif echo "$UID_OUT" | grep -q "no card"; then
    echo "SKIP (no card detected — check physical placement)"; ((skip++))
    echo "  STOPPING: no card on reader"
    exit 1
else
    echo "FAIL (got: $UID_OUT)"; ((fail++))
fi

echo "--- 2. Read-only inspection ---"
t "ver"        $CLI $READER ver
t "inspect"    $CLI $READER inspect
t "picc"       $CLI $READER picc --issuer-key $ISSUER
t "url"        $CLI $READER url

echo "--- 3. Key verification ---"
t "try-key K0" $CLI $READER try-key --key 2ac7a4cdbfc53878a807e30acc7f88ac --key-no 0 --attempts 30
t "keyver"     $CLI $READER keyver --issuer-key $ISSUER --version 1

echo "--- 4. Auth budget (read-only) ---"
$CLI budget 2>/dev/null | head -3 || true

echo ""
echo "=== Results: $pass pass / $fail fail / $skip skip ==="
[ "$fail" -eq 0 ]
