#!/usr/bin/env python3
"""union_matrix.py — ONE source of truth for the bolty union compile matrix.

Kanban t_f579fc05 (union matrix CI): the valid board x frontend x transport
combos are PARSED LIVE from apps/bolty-esp32/build.sh — the bench flow is
the authority — plus a static table for the STM32 frontend cross (no bench
build.sh exists there yet). The workflow generates its matrix from this
script (`--format matrix`), so a new build.sh case can never be silently
skipped, and an invalid entry (feature that no longer exists, sdkconfig
that was renamed) fails LOUDLY here (`check` mode) at the construction
seam instead of rotting a matrix leg.

Cross-repo note: this is bolty's half of the union matrix; the ccid
half (backend x board x transport x mode for esp32-ccid) lives in
ccid-firmware-rs tools/union_matrix.py. Same CLI, same rules.

Modes:
  check                     validate everything (features exist in the
                            manifests, sdkconfig files exist, build.sh
                            parses, selftest) — exit 1 on drift
  selftest                  parse a synthetic fixture; assert parser
                            invariants
  --format matrix           GitHub `matrix.include` JSON for the esp32 legs
  --format stm32-matrix     GitHub matrix JSON for the stm32 frontend cross
  --format table            human-readable combo table
  --format commands         local entrypoint: exact cargo incantation per
                            variant (env exports included)
  --variant <name>          restrict output to one variant
  --filter <substr>         restrict output to variants whose name contains
                            substr (workflow_dispatch smoke runs)

Exit codes: 0 ok, 1 validation failure / unknown variant.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_SH = REPO_ROOT / "apps" / "bolty-esp32" / "build.sh"
ESP_DIR = REPO_ROOT / "apps" / "bolty-esp32"
ESP_MANIFEST = ESP_DIR / "Cargo.toml"
STM32_MANIFEST = REPO_ROOT / "apps" / "bolty-stm32" / "Cargo.toml"

# sdkconfig per variant: build.sh defaults to sdkconfig.defaults for every
# case; the BLE experiment requires the feature AND its config to travel
# together (see build.sh usage note) — encoded here so CI can never build
# ble against the plain defaults.
SDKCONFIGS = {
    "m5stick-ble": "sdkconfig.defaults.ble",
}
DEFAULT_SDKCONFIG = "sdkconfig.defaults"

# STM32 frontend cross — no build.sh on this side; the table mirrors
# apps/bolty-stm32/Cargo.toml [features] (board-stm32f4-disco is the only
# board; nfc-mfrc522 ships, nfc-pn532 is the F469 revival spike #163).
STM32_COMBOS = [
    {
        "name": "stm32f4-disco-mfrc522",
        "features": "board-stm32f4-disco,nfc-mfrc522",
        "provenance": "stm32-check.yml (shipped build)",
    },
    {
        "name": "stm32f4-disco-pn532",
        "features": "board-stm32f4-disco,nfc-pn532",
        "provenance": "nfc-pn532 revival spike (#163) — union-only leg",
    },
]

CASE_LINE_RE = re.compile(
    r'^\s{4}([a-z0-9-]+)\)\s+FEATURES="([^"]*)";\s+TRIPLE="([^"]+)"',
    re.MULTILINE,
)


def parse_build_sh(text: str) -> list[dict]:
    """Parse the `case "$BOARD" in` FEATURES/TRIPLE lines of build.sh."""
    start = text.index('case "$BOARD" in')
    end = text.index("\nesac", start)
    block = text[start:end]
    combos = []
    for m in CASE_LINE_RE.finditer(block):
        name, features, triple = m.groups()
        if name == "*":
            continue
        combos.append(
            {
                "name": name,
                "features": features,
                "target": triple,
                "sdkconfig": SDKCONFIGS.get(name, DEFAULT_SDKCONFIG),
                "sdkconfig_override": name in SDKCONFIGS,
                "provenance": "build.sh",
            }
        )
    return combos


def manifest_features(path: Path) -> set[str]:
    with open(path, "rb") as f:
        return set(tomllib.load(f).get("features", {}).keys())


def check() -> list[str]:
    """Full validation; returns error strings (empty == healthy)."""
    errors: list[str] = []
    try:
        combos = parse_build_sh(BUILD_SH.read_text())
    except (OSError, ValueError) as e:
        return [f"build.sh parse failed: {e}"]

    if len(combos) < 5:
        errors.append(f"build.sh yielded only {len(combos)} cases — parser drift?")

    known_esp = manifest_features(ESP_MANIFEST)
    for c in combos:
        for feat in filter(None, c["features"].split(",")):
            if feat not in known_esp:
                errors.append(f"{c['name']}: feature {feat!r} not in bolty-esp32 [features]")
        if c["target"] not in ("xtensa-esp32-espidf", "riscv32imc-esp-espidf"):
            errors.append(f"{c['name']}: unexpected target {c['target']}")
        if not (ESP_DIR / c["sdkconfig"]).exists():
            errors.append(f"{c['name']}: sdkconfig {c['sdkconfig']!r} missing under apps/bolty-esp32/")
        if not c["features"]:
            errors.append(f"{c['name']}: empty feature list — malformed entry")

    known_stm32 = manifest_features(STM32_MANIFEST)
    for c in STM32_COMBOS:
        for feat in c["features"].split(","):
            if feat not in known_stm32:
                errors.append(f"{c['name']}: feature {feat!r} not in bolty-stm32 [features]")

    names = [c["name"] for c in combos]
    if len(names) != len(set(names)):
        errors.append(f"duplicate variant names: {sorted(names)}")

    errors.extend(selftest(quiet=True))
    return errors


SELFTEST_FIXTURE = '''#!/usr/bin/env bash
case "$BOARD" in
    alpha)     FEATURES="board-alpha,wifi,rest"; TRIPLE="xtensa-esp32-espidf" ;;
    beta)      FEATURES="board-beta";             TRIPLE="riscv32imc-esp-espidf" ;;
    *)         usage ;;
esac
'''


def selftest(quiet: bool = False) -> list[str]:
    errors: list[str] = []
    try:
        cases = parse_build_sh(SELFTEST_FIXTURE)
    except ValueError as e:
        return [f"selftest parse failed: {e}"]
    expect = [
        {"name": "alpha", "features": "board-alpha,wifi,rest", "target": "xtensa-esp32-espidf"},
        {"name": "beta", "features": "board-beta", "target": "riscv32imc-esp-espidf"},
    ]
    got = [{k: c[k] for k in ("name", "features", "target")} for c in cases]
    if got != expect:
        errors.append(f"selftest: parser output drifted: {got!r}")
    if not quiet:
        print("selftest: OK" if not errors else f"selftest: FAILED {errors}")
    return errors


def dims(combo: dict) -> str:
    """Human dimension summary (board x frontend x transport)."""
    f = set(combo["features"].split(","))
    board = next((x for x in f if x.startswith("board-")), "?")
    # board features imply their frontend through the manifest (board-nucula
    # = nfc-pn7160; board-m5stick/board-m5atom = nfc-mfrc522).
    if "board-nucula" in f:
        frontend = "pn7160"
    elif any(b in f for b in ("board-m5stick", "board-m5atom")):
        frontend = "mfrc522"
    else:
        frontend = next((x.removeprefix("nfc-") for x in f if x.startswith("nfc-")), "?")
    transports = [t for t in ("wifi", "rest", "ota", "ota-server", "ble") if t in f]
    transport = "+".join(transports) if transports else "serial-console"
    return f"{board.removeprefix('board-')} x {frontend} x {transport}"


def select(combos: list[dict], variant: str | None, filt: str | None) -> list[dict]:
    out = combos
    if variant:
        out = [c for c in out if c["name"] == variant]
        if not out:
            sys.exit(f"error: unknown variant {variant!r} (see --format table)")
    if filt:
        out = [c for c in out if filt in c["name"]]
    return out


def main() -> int:
    args = sys.argv[1:]
    fmt = "check"
    if args and args[0] == "selftest":
        return 1 if selftest() else 0
    if args and args[0] == "check":
        args = args[1:]
    elif args and args[0] == "--format":
        fmt = args[1]
        args = args[2:]
    variant = filt = None
    while args:
        if args[0] == "--variant":
            variant = args[1]
            args = args[2:]
        elif args[0] == "--filter":
            filt = args[1]
            args = args[2:]
        else:
            sys.exit(f"error: unknown arg {args[0]!r}")

    if fmt == "check":
        errs = check()
        for e in errs:
            print(f"ERROR: {e}", file=sys.stderr)
        if errs:
            return 1
        combos = parse_build_sh(BUILD_SH.read_text())
        print(f"union matrix OK: {len(combos)} esp32 combos, {len(STM32_COMBOS)} stm32 combos")
        return 0

    combos = select(parse_build_sh(BUILD_SH.read_text()), variant, filt)

    if fmt == "matrix":
        print(json.dumps(combos, separators=(",", ":")))
    elif fmt == "stm32-matrix":
        print(json.dumps(STM32_COMBOS, separators=(",", ":")))
    elif fmt == "table":
        print(f"{'variant':<18} {'target':<24} dims (board x frontend x transport)")
        for c in combos:
            print(f"{c['name']:<18} {c['target']:<24} {dims(c)}  [{c['provenance']}]")
        for c in STM32_COMBOS:
            print(f"{c['name']:<18} {'thumbv7em-none-eabihf':<24} stm32 frontend cross  [{c['provenance']}]")
    elif fmt == "commands":
        for c in combos:
            print(f"# --- {c['name']} ({dims(c)}) [{c['provenance']}]")
            print("cd apps/bolty-esp32")
            if c["sdkconfig_override"]:
                print(f'export ESP_IDF_SDKCONFIG_DEFAULTS="$PWD/{c["sdkconfig"]}"')
            print(f'cargo +esp check --target {c["target"]} --features "{c["features"]}"')
            print()
        for c in STM32_COMBOS:
            print(f"# --- {c['name']} [{c['provenance']}]")
            print(f'cargo check -p bolty-stm32 --target thumbv7em-none-eabihf --features "{c["features"]}"')
            print()
    else:
        sys.exit(f"error: unknown format {fmt!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
