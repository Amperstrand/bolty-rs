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

COORDINATOR="${LABGRID_COORDINATOR:-192.168.13.221:20408}"
EXPORTER_NAME="${LABGRID_EXPORTER_NAME:-ai-legion-small}"

BOARD_PLACE() {  # $1 = token resource, $2 = match class, $3 = place suffix
    local p="bolty-$3"
    labgrid-client -x "$COORDINATOR" -p "$p" create 2>/dev/null || true
    labgrid-client -x "$COORDINATOR" -p "$p" \
        add-match "${EXPORTER_NAME}/$1/$2" 2>/dev/null || true
    labgrid-client -x "$COORDINATOR" -p "$p" \
        set-comment "state record for $3 (tags: firmware/test/owner/ts)" \
        2>/dev/null || true
}

BOARD_PLACE m5stick-serial NetworkSerialPort      m5stick
BOARD_PLACE acr1252        NetworkSmartcardReader acr1252

labgrid-client -x "$COORDINATOR" -p bolty-m5stick show | sed -n '1,4p'
labgrid-client -x "$COORDINATOR" -p bolty-acr1252 show | sed -n '1,4p'
