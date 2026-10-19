#!/usr/bin/env bash
# Idempotently (re)create the bolty-rig place with its resource matches.
# Coordinator restarts wipe in-memory place definitions — run this after
# any labgrid-coordinator restart (or when acquire says "matches nothing").
set -euo pipefail

COORDINATOR="${LABGRID_COORDINATOR:-192.168.13.208:20408}"
PLACE="bolty-rig"

lg() { labgrid-client -x "$COORDINATOR" -p "$PLACE" "$@"; }

if lg show >/dev/null 2>&1; then
    echo "place $PLACE exists"
else
    lg create
    echo "place $PLACE created"
fi

# Post-2026-09-26 consolidation resource names (this host's exporter):
# matches the rig's stick USB serial + the ACR1252 reference reader.
lg add-match 'ai-legion-nfc/m5stick-usb/SerialPort'
lg add-match 'ai-legion-nfc/ref-acr1252/USBDevice'
lg show | sed -n '1,4p'
