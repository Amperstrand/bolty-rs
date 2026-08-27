#!/usr/bin/env bash
# proxy_healthcheck.sh — detect psbt.me Cloudflare-tunnel outages.
#
# Observed 2026-08-26/27: proxy.psbt.me intermittently returns HTTP 530
# (Cloudflare error 1033 — Argo tunnel down) while the origin process may be
# fine. Bolt-card taps silently fail while this state lasts. This check runs
# from systemd (proxy-healthcheck.timer) and logs state transitions to the
# journal (journalctl -t bolty-proxy-health).
#
# Healthy = any HTTP status that is NOT a 52x/530/000 (the app answering
# 4xx for a bare /ln request proves the origin is reachable and executing).

set -u
URL="${1:-https://proxy.psbt.me/ln}"
STATE_FILE="/var/tmp/bolty-proxy-health.state"
TAG="bolty-proxy-health"

status=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "$URL" 2>/dev/null || echo 000)

if [ "$status" -ge 520 ] && [ "$status" -le 599 ] || [ "$status" = "000" ]; then
    verdict="DOWN"
else
    verdict="UP"
fi

prev="unknown"
[ -f "$STATE_FILE" ] && prev=$(cat "$STATE_FILE")

if [ "$verdict" != "$prev" ]; then
    logger -t "$TAG" "proxy $URL state change: $prev -> $verdict (http=$status)"
    echo "$verdict" > "$STATE_FILE"
else
    [ "$verdict" = "DOWN" ] && logger -t "$TAG" "proxy $URL still DOWN (http=$status)"
fi

exit 0
