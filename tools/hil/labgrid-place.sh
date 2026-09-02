#!/usr/bin/env bash
# Idempotently (re)create the bolty-rig place with its resource matches.
# Coordinator restarts wipe in-memory place definitions — run this after
# any labgrid-coordinator restart (or when acquire says "matches nothing").
set -euo pipefail

COORDINATOR="${LABGRID_COORDINATOR:-192.168.13.221:20408}"
PLACE="bolty-rig"

lg() { labgrid-client -x "$COORDINATOR" -p "$PLACE" "$@"; }

if lg show >/dev/null 2>&1; then
    echo "place $PLACE exists"
else
    lg create
    echo "place $PLACE created"
fi

lg add-match 'ai-legion-small/m5stick-serial/NetworkSerialPort'
lg add-match 'ai-legion-small/acr1252/NetworkSmartcardReader'
lg show | sed -n '1,4p'
