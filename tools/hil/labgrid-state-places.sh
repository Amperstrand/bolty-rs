#!/usr/bin/env bash
# Idempotently (re)create the per-board DOCUMENTATION places for bolty
# hardware (docs/labgrid-bench-sharing.md P2, microfips microfips-<alias>
# pattern): never acquired for exclusivity (that is bolty-rig + the
# amperstrand-bench flock) — they carry state tags (firmware/test/owner/ts)
# mirrored by hil.note_rig_state, so any project or machine can ask labgrid
# what a bolty board currently runs. Coordinator restarts wipe in-memory
# place definitions — run this after any labgrid-coordinator restart.
#
# Match classes are the coordinator-visible names (`labgrid-client
# resources`), NOT the exporter-yaml class keys: m5stick-serial exports
# USBSerialPort and surfaces as NetworkSerialPort (AGENTS.md exports[]-map
# trap; the working bolty-rig matches prove it).
set -euo pipefail

COORDINATOR="${LG_COORDINATOR:-192.168.13.208:20408}"
## 2026-11-12 audit: live resource paths (labgrid-client resources). The
## pre-re-home names (ai-legion-small/m5stick-serial, ai-legion-small/acr1252)
## no longer exist — the stick serial is bridged to ai-legion as
## ai-legion-nfc/m5stick-usb, and the ACR1252 physically lives on
## ai-legion-small, exported as ai-legion-small-nfc/acr1252. Match strings
## must be the full group/name/class as listed by `resources`.

BOARD_PLACE() {  # $1 = full match, $2 = place suffix
    local p="bolty-$2"
    labgrid-client -x "$COORDINATOR" -p "$p" create 2>/dev/null || true
    labgrid-client -x "$COORDINATOR" -p "$p" \
        add-match "$1" 2>/dev/null || true
    labgrid-client -x "$COORDINATOR" -p "$p" \
        set-comment "state record for $2 (tags: firmware/test/owner/ts)" \
        2>/dev/null || true
}

BOARD_PLACE 'ai-legion-nfc/m5stick-usb/SerialPort'                 m5stick
BOARD_PLACE 'ai-legion-small-nfc/acr1252/NetworkSmartcardReader'   acr1252

labgrid-client -x "$COORDINATOR" -p bolty-m5stick show | sed -n '1,4p'
labgrid-client -x "$COORDINATOR" -p bolty-acr1252 show | sed -n '1,4p'
