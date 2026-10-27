#!/usr/bin/env python3
"""H1 ACR lane: post-#120 burn-cycle regression (Phase A executor).

burn_cycle.py semantics, ACR1252/BoltyCli transport (the stick runs
nucula — console path is off-limits). Per cycle:

  burn (deterministic issuer, boltcardpoc URL template, --confirm-uid)
  -> inspect          PROVISIONED + CMAC_valid=true
  -> picc             SDM verification PASSED, UID matches YES, CMAC valid YES
  -> live worker tap  GET <base>?p=<32hex>&c=<16hex> -> HTTP 200
  -> wipe             "wiped and verified successfully"
  -> diagnose         Card state: BLANK

Exit 0 only if N/N cycles ALL-PASS including live taps. First unexpected
failure stops the run immediately (mission rule: no proceeding past a
red stage); evidence is kept either way.

Preconditions (asserted, never assumed):
  - BOLTY_READER pins the ACR1252 PICC interface (stable identity, not
    enumeration order — the slot index drifts between sessions)
  - coupled UID == --uid and cards.toml grants burn+wipe for it
  - B32 acr_probe reports ok (no wedge)

Smoke-testing without hardware: set BOLTY_CLI_BIN to a stub that emits
the canned stage outputs, --tap-base http://127.0.0.1:PORT/ and a local
http.server returning 200 — validates control flow + assertions only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HIL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(HIL_ROOT))

from hil import BoltyCli, BoltyError, CardRegistry          # noqa: E402
from hil.acr_probe import probe_isolated                    # noqa: E402

READER_NEEDLE = os.environ.get("BOLTY_READER", "ACR1252 Dual Reader PICC")
PUBLIC_ISSUER = "0" * 31 + "1"   # well-known public dev issuer (B12), v1
URL_TEMPLATE = os.environ.get(
    "HIL_URL", "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}"
)
TAP_BASE_DEFAULT = URL_TEMPLATE.split("?")[0]

STATE_BLANK = "Card state:     BLANK"
STATE_PROVISIONED = "Card state:     PROVISIONED"
BURN_OK = "burned and verified successfully"
WIPE_OK = "wiped and verified successfully"


def log(ts_path: Path, msg: str) -> None:
    line = f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    with ts_path.open("a") as fh:
        fh.write(line + "\n")


def run_stage(cli: BoltyCli, transcript: Path, name: str, *args: str) -> str:
    t0 = time.monotonic()
    out = cli.run(*args)
    dt = time.monotonic() - t0
    with transcript.open("a") as fh:
        fh.write(f"\n===== {name} ({dt:.2f}s) =====\n$ bolty-cli {' '.join(args)}\n{out}\n")
    return out


def http_code(tap_url: str, transcript: Path) -> str:
    t0 = time.monotonic()
    p = subprocess.run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "20", tap_url],
        capture_output=True, text=True, timeout=30,
    )
    dt = time.monotonic() - t0
    with transcript.open("a") as fh:
        fh.write(f"\n===== live worker tap ({dt:.2f}s) =====\nGET {tap_url} -> {p.stdout.strip()}\n")
    return p.stdout.strip()


def one_cycle(cli: BoltyCli, registry: CardRegistry, uid: str, issuer: str,
              tap_base: str, cycle: int, evidence: Path, emu: bool = False) -> dict:
    transcript = evidence / f"cycle-{cycle:02d}.log"
    transcript.write_text(
        f"# H1 Phase A cycle {cycle} — {datetime.now(timezone.utc).isoformat()}\n"
        f"# reader pin: {READER_NEEDLE}\n"
    )
    results: dict[str, bool] = {}

    out = run_stage(cli, transcript, "burn", "burn", "--issuer-key", issuer,
                    "--url", URL_TEMPLATE, "--confirm-uid", uid)
    results["burn"] = BURN_OK in out

    out = run_stage(cli, transcript, "inspect provisioned", "inspect",
                    "--issuer-key", issuer)
    results["inspect_provisioned"] = (
        "K0 auth: SUCCESS" in out and "CMAC_valid=true" in out
    )

    out = run_stage(cli, transcript, "picc", "picc", "--issuer-key", issuer)
    if emu:
        results["picc_sdm_ok"] = "CMAC valid:     YES" in out
        m_um = re.search(r"UID matches:\s+(YES|NO)", out)
        log(transcript, f"emu note: picc uid_match={m_um.group(1) if m_um else chr(63)}"
            " (install-UID artifact, expected mismatch)")
    else:
        results["picc_sdm_ok"] = (
            "SDM verification PASSED" in out
            and "UID matches:    YES" in out
            and "CMAC valid:     YES" in out
        )
    m_p = re.search(r"p = ([0-9A-Fa-f]{32})", out)
    m_c = re.search(r"c = ([0-9A-Fa-f]{16})", out)
    if m_p and m_c and results["picc_sdm_ok"]:
        tap_url = f"{tap_base}?p={m_p.group(1)}&c={m_c.group(1)}"
        results["worker_tap_200"] = http_code(tap_url, transcript) == "200"
    else:
        results["worker_tap_200"] = False

    wipe_cmd = ["wipe", "--issuer-key", issuer, "--confirm-uid", uid]
    if emu:
        wipe_cmd.append("--skip-preverify")
    out = run_stage(cli, transcript, "wipe", *wipe_cmd)
    results["wipe"] = WIPE_OK in out

    out = run_stage(cli, transcript, "diagnose blank", "diagnose",
                    "--issuer-key", issuer)
    results["state_blank"] = STATE_BLANK in out

    ok = all(results.values())
    summary = {
        "cycle": cycle, "ts": datetime.now(timezone.utc).isoformat(),
        "results": results, "all_pass": ok,
    }
    with (evidence / "summary.jsonl").open("a") as fh:
        fh.write(json.dumps(summary) + "\n")
    log(transcript, f"cycle {cycle}: {'ALL PASS' if ok else 'FAIL — ' + str(results)}")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cycles", type=int, default=6)
    ap.add_argument("--uid", default=os.environ.get("HIL_UID", "04c474fa967380"))
    ap.add_argument("--issuer", default=PUBLIC_ISSUER)
    ap.add_argument("--tap-base", default=TAP_BASE_DEFAULT)
    ap.add_argument("--evidence", default="/tmp/opencode/boltcard2/h1-acr")
    ap.add_argument("--emu-card", action="store_true",
                    help="emulator personality: wipe skips p/c preverify (known install-UID"
                         " artifact), picc asserts SDM+CMAC and logs uid_match instead of"
                         " requiring it")
    args = ap.parse_args()

    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    ts = evidence / "harness.log"

    cli_bin = os.environ.get("BOLTY_CLI_BIN")
    cli = BoltyCli(binary=Path(cli_bin)) if cli_bin else BoltyCli()

    # ---- preflight -------------------------------------------------------
    probe = (
        {"state": "skipped", "detail": "H1_SKIP_PROBE=1 (smoke mode)"}
        if os.environ.get("H1_SKIP_PROBE") == "1"
        else probe_isolated()
    )
    log(ts, f"acr probe: {probe['state']} ({probe['detail']})")
    if probe["state"] not in ("ok", "skipped"):
        log(ts, "PREFLIGHT FAIL: ACR not ok — stop (B32 rule)")
        return 2

    reader = cli.readers_line()
    log(ts, f"reader: {reader}")
    if READER_NEEDLE not in reader:
        log(ts, f"PREFLIGHT FAIL: reader not pinned to {READER_NEEDLE!r}")
        return 2

    registry = CardRegistry(HIL_ROOT / "hil" / "cards.toml")
    registry.require(args.uid, "burn")
    registry.require(args.uid, "wipe")
    log(ts, f"registry ok: {args.uid} burn+wipe")

    uid = cli.uid()
    if uid != args.uid:
        log(ts, f"PREFLIGHT FAIL: coupled {uid} != expected {args.uid} — refusing")
        return 2
    log(ts, f"coupled card: {uid}")

    diag = cli.run("diagnose", "--issuer-key", args.issuer)
    if STATE_BLANK not in diag:
        # Factory-keyed cards (K0=zeros, e.g. residual test NDEF written via
        # plain ISO writes) burn directly — burn starts with factory auth.
        try:
            probe = cli.run("try-key", "--key", "0" * 32)
        except BoltyError:
            probe = ""
        if "Key accepted" in probe:
            log(ts, "factory-keyed card with residual NDEF — burn will take it from here")
        else:
            log(ts, "card not blank at start — one bounded wipe to lab-stock state")
            pre = ["wipe", "--issuer-key", args.issuer, "--confirm-uid", args.uid]
            if args.emu_card:
                pre.append("--skip-preverify")
            out = cli.run(*pre)
            if WIPE_OK not in out:
                log(ts, "PREFLIGHT FAIL: start-state wipe failed — stop")
                return 2

    # ---- cycles ----------------------------------------------------------
    passes = 0
    for cycle in range(1, args.cycles + 1):
        try:
            summary = one_cycle(cli, registry, args.uid, args.issuer,
                                args.tap_base, cycle, evidence, emu=args.emu_card)
        except BoltyError as exc:
            log(ts, f"cycle {cycle}: UNEXPECTED CLI FAILURE — stop. {exc}")
            return 1
        if not summary["all_pass"]:
            log(ts, f"cycle {cycle} failed — mission stop rule; not proceeding")
            return 1
        passes += 1

    log(ts, f"VERDICT: {passes}/{args.cycles} ALL-PASS"
        f" (live taps included)" if passes == args.cycles else "incomplete")
    return 0 if passes == args.cycles else 1


if __name__ == "__main__":
    sys.exit(main())
