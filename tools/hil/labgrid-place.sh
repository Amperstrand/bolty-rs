#!/usr/bin/env bash
# Idempotently (re)create the bolty labgrid places with their resource
# matches. Coordinator restarts wipe in-memory place definitions — run this
# after any labgrid-coordinator restart (or when acquire says "matches
# nothing").
set -euo pipefail

COORDINATOR="${LG_COORDINATOR:-192.168.13.208:20408}"

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

# drop_match <place> <match>
# Removes a match that is KNOWN to have moved (2026-10-25 ACR retirement
# from ai-legion-nfc). Without this, ensure_place would happily re-add
# phantom matches to already-migrated places — a place carrying a match
# with no live resource cannot acquire ("matches nothing"), so the
# cleanup is required for idempotence, not cosmetic.
drop_match() {
    local place="$1" match="$2"
    if lg -p "$place" show | grep -qxF "    $match"; then
        lg -p "$place" del-match "$match"
        echo "match $match REMOVED (moved/retired resource)"
    fi
}

# Full rig (Phase-2 burn_cycle, difftest): stick serial + reference ACR.
# 2026-11-12 audit: the ACR1252 physically lives on ai-legion-small since
# 2026-10-25 — exported as ai-legion-small-nfc/acr1252/NetworkSmartcardReader
# (formal exporter: labgrid-exporter-nfc-small.service on small, config
# conwrt-bench/deploy/exporter-nfc-small.yaml). The old
# ai-legion-nfc/ref-acr1252/USBDevice export is RETIRED — drop any stale
# match before ensuring the live one.
drop_match bolty-rig 'ai-legion-nfc/ref-acr1252/USBDevice'
ensure_place bolty-rig \
    'ai-legion-nfc/m5stick-usb/SerialPort' \
    'ai-legion-small-nfc/acr1252/NetworkSmartcardReader'

# ACR-only leaf (#127): one-device-one-exclusion-domain. ACR-only suites
# (make test-hil fast path, Phase-1) acquire this place and are no longer
# blocked by stick-serial holders. Same retirement cleanup as bolty-rig —
# the coordinator's ref-acr1252 was already re-pointed by hand; running
# this script must not resurrect the phantom on top of it.
drop_match ref-acr1252 'ai-legion-nfc/ref-acr1252/USBDevice'
ensure_place ref-acr1252 'ai-legion-small-nfc/acr1252/NetworkSmartcardReader'
