#!/usr/bin/env bash
# Idempotently (re)create the bolty labgrid places with their resource
# matches. Coordinator restarts wipe in-memory place definitions — run this
# after any labgrid-coordinator restart (or when acquire says "matches
# nothing").
set -euo pipefail

COORDINATOR="${LABGRID_COORDINATOR:-192.168.13.208:20408}"

lg() { labgrid-client -x "$COORDINATOR" "$@"; }

# ensure_place <name> <match> [<match>...]
# Check-first idempotence (Codex P2 on #164): read the place's current
# matches from `show` and only add what is missing. Unconditional
# add-match is NOT portable — labgrid 26.0's AddPlaceMatch returns
# ALREADY_EXISTS for a duplicate and `set -e` would abort the script
# before later ensure_place calls run (the deployed 25.x coordinator
# only warns "exists, skipping", so this is defense against upgrade).
ensure_place() {
    local place="$1"; shift
    if lg -p "$place" show >/dev/null 2>&1; then
        echo "place $place exists"
    else
        lg -p "$place" create
        echo "place $place created"
    fi
    local match
    for match in "$@"; do
        # `show` lists current matches indented by 4 spaces under "matches:"
        if lg -p "$place" show | grep -qxF "    $match"; then
            echo "match $match already present"
        else
            lg -p "$place" add-match "$match"
            echo "match $match added"
        fi
    done
    lg -p "$place" show | sed -n '1,4p'
}

# Full rig (Phase-2 burn_cycle, difftest): stick serial + reference ACR.
# Post-2026-09-26 consolidation resource names (this host's exporter).
ensure_place bolty-rig \
    'ai-legion-nfc/m5stick-usb/SerialPort' \
    'ai-legion-nfc/ref-acr1252/USBDevice'

# ACR-only leaf (#127): one-device-one-exclusion-domain. ACR-only suites
# (make test-hil fast path, Phase-1) acquire this place and are no longer
# blocked by stick-serial holders.
ensure_place ref-acr1252 'ai-legion-nfc/ref-acr1252/USBDevice'
