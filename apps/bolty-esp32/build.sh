#!/usr/bin/env bash
# build.sh — verified bench build for bolty-esp32.
#
# Encodes the hard-won build traps from the shared Amperstrand bench
# (full history: docs/lessons-learned.md B30, ccid-firmware-rs build.sh):
#
#   1. CARGO_WORKSPACE_DIR must be pinned — the esp-idf-sys build script
#      locates the workspace by popping OUT_DIR six levels; under a shared
#      global target dir (~/.cargo/config.toml on ai-legion points every
#      checkout at /root/.cargo-target) that resolves INSIDE the target
#      dir and the build silently pins whatever ESP-IDF the stale state
#      holds. Observed again on this box 2026-10-12: a v5.5.5 manifest pin
#      produced a v5.2.3 firmware binary.
#   2. CARGO_TARGET_DIR defaults to the workspace ./target (NOT the global
#      shared dir) so bolty and ccid-firmware-rs never cross-contaminate
#      esp-idf-sys artifacts for the same triple.
#   3. Changing esp_idf_version in Cargo.toml (and switching
#      --sdkconfig variants) does NOT reliably rerun the build script —
#      use --clean-sys after either.
#   4. Every build verifies the resolved esp_idf_dir against the manifest
#      pin and the generated sdkconfig against the requested defaults,
#      failing LOUDLY on mismatch (see verify_idf_pin /
#      verify_sdkconfig_fresh).
#
# Usage:
#   ./build.sh <m5stick|m5stick-min|m5atom|m5stick-ble> [--flash <port>]
#              [--clean-sys] [--sdkconfig <file>]
#
#   m5stick      board-m5stick,wifi,rest,ota   (the canonical bench build)
#   m5stick-min  board-m5stick                 (serial console only)
#   m5atom       board-m5atom
#   m5stick-ble  board-m5stick,ble             (BLE experiment; pairs with
#                --sdkconfig sdkconfig.defaults.ble — the sdkconfig and the
#                feature must travel together or the bt module is either
#                absent from the build or uncompilable)
#
# --sdkconfig passes an alternative ESP_IDF_SDKCONFIG_DEFAULTS file
# (relative to this directory), e.g. sdkconfig.defaults.ble for the BLE
# experiment — never edit sdkconfig.defaults itself for BT work: enabling
# Bluedroid there compiles the esp-idf-svc bt module for EVERY config.
#
# --flash <port> flashes via espflash after a successful verified build
# (115200 baud — the FT232 link drops bytes above that; lessons B2/B3).

set -euo pipefail

# Non-interactive shells (cron, CI, ssh) lack ~/.cargo/bin on PATH.
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CARGO_WORKSPACE_DIR="${SCRIPT_DIR}/../.."

# Isolate from the global shared target dir (trap 2). Honor an explicit
# CARGO_TARGET_DIR for CI parity runs.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${SCRIPT_DIR}/../../target}"

# Gentle on the shared bench box: the IDF cmake/ninja build defaults to
# nproc jobs and has pushed ai-legion into swap thrash with other agent
# sessions running (2026-10-12).
export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-4}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1
}

[ $# -ge 1 ] || usage
BOARD="$1"; shift || true

FEATURES=""
case "$BOARD" in
    m5stick)     FEATURES="board-m5stick,wifi,rest,ota" ;;
    m5stick-min) FEATURES="board-m5stick" ;;
    m5atom)      FEATURES="board-m5atom" ;;
    m5stick-ble) FEATURES="board-m5stick,ble" ;;
    *)           usage ;;
esac

FLASH_PORT=""
CLEAN_SYS=0
SDKCONFIG="sdkconfig.defaults"
while [ $# -gt 0 ]; do
    case "$1" in
        --flash)     FLASH_PORT="${2:?--flash needs a port}"; shift 2 ;;
        --clean-sys) CLEAN_SYS=1; shift ;;
        --sdkconfig) SDKCONFIG="${2:?--sdkconfig needs a file}"; shift 2 ;;
        *)           usage ;;
    esac
done

cd "$SCRIPT_DIR"

# The esp-idf pin travels in Cargo.toml (single source of truth).
IDF_PIN="$(grep -oP 'esp_idf_version\s*=\s*"tag:\Kv[0-9]+\.[0-9]+\.[0-9]+' Cargo.toml || true)"
[ -n "$IDF_PIN" ] || die "cannot parse esp_idf_version tag out of Cargo.toml"

if [ "$CLEAN_SYS" -eq 1 ]; then
    info "cleaning esp-idf-sys build state (post-bump rerun rule)"
    rm -rf "$CARGO_TARGET_DIR"/xtensa-esp32-espidf/release/build/esp-idf-sys-*
fi

verify_idf_pin() {
    local json dir
    json="$(ls "$CARGO_TARGET_DIR"/xtensa-esp32-espidf/release/build/esp-idf-sys-*/out/esp-idf-build.json 2>/dev/null | head -n1 || true)"
    [ -n "$json" ] || die "no esp-idf-build.json under $CARGO_TARGET_DIR — did the build run?"
    dir="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['esp_idf_dir'])" "$json")"
    case "$dir" in
        *"$IDF_PIN")
            info "resolved esp_idf_dir: $dir"
            ;;
        *)
            die "firmware resolved $dir but the manifest pins $IDF_PIN — the pin was IGNORED (stale .embuild / esp-idf-sys state). Run: $0 $BOARD --clean-sys"
            ;;
    esac
}

verify_sdkconfig_fresh() {
    # Env/default changes do not reliably rerun the esp-idf-sys build script,
    # and relative sdkconfig paths resolve against the WORKSPACE root (where
    # they don't exist) — both observed 2026-10-12, leaving the bt module
    # configured-out under a --sdkconfig sdkconfig.defaults.ble build. This
    # gate checks the build actually CONSUMED the requested defaults file:
    # embuild records the resolved list in esp-idf-build.json.
    local json used
    json="$(ls "$CARGO_TARGET_DIR"/xtensa-esp32-espidf/release/build/esp-idf-sys-*/out/esp-idf-build.json 2>/dev/null | head -n1 || true)"
    [ -n "$json" ] || return 0
    used="$(python3 -c '
import json, sys
info = json.load(open(sys.argv[1]))
for p in info.get("sdkconfig_defaults") or []:
    print(p)
' "$json")"
    case "$used" in
        *"$SCRIPT_DIR/$SDKCONFIG"*)
            info "sdkconfig defaults consumed: $SCRIPT_DIR/$SDKCONFIG"
            ;;
        *)
            die "the running build did NOT consume $SDKCONFIG (resolved: ${used:-none}) — sdkconfig switches need: $0 $BOARD --clean-sys"
            ;;
    esac
}

info "building bolty-esp32 [$BOARD] features=$FEATURES (target-dir=$CARGO_TARGET_DIR)"
info ". ~/export-esp.sh must have been sourced or espup installed"
if [ -f "$HOME/export-esp.sh" ]; then
    # shellcheck disable=SC1091
    . "$HOME/export-esp.sh"
fi
command -v ldproxy >/dev/null || die "ldproxy not found — run espup install and source ~/export-esp.sh"

# Absolute path: relative sdkconfig paths resolve against the WORKSPACE root
# in esp-idf-sys, where the variant files do not exist.
ESP_IDF_SDKCONFIG_DEFAULTS="$SCRIPT_DIR/$SDKCONFIG" \
    cargo +esp build --release --features "$FEATURES"
verify_idf_pin
verify_sdkconfig_fresh

BIN="$CARGO_TARGET_DIR/xtensa-esp32-espidf/release/bolty-esp32"
[ -f "$BIN" ] || die "build finished but $BIN is missing"

if [ -n "$FLASH_PORT" ]; then
    info "flashing $BIN to $FLASH_PORT at 115200"
    espflash flash --baud 115200 --port "$FLASH_PORT" "$BIN"
fi

info "done: $BIN (IDF $IDF_PIN verified)"
