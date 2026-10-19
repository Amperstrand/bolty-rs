#!/usr/bin/env python3
"""Nucula extensive bench cycle: visit-gated runner (plan v2, 2026-10-19).

Two-card ping-pong between the ACR1252 reference reader (burner/oracle) and
the nucula PN7160 reader (DUT, via the pcscd CCID broker + BOLTY_READER pin).
Owner hands are scarce: every physical move is a VISIT, software owns all
gating between visits (UID verified before any batch; wrong card ⇒ loud
abort, zero mutation; registry is the contract). Visits are asynchronous —
the bench idles between them, places are released per batch.

Visit schedule (full variant; minimal = V1-V3, CARD_B never burned):
  V1  setup: CARD_B→nucula antenna, CARD_A→ACR. Runs: nucula read battery on
      CARD_B ‖ ACR burn vertical on CARD_A (burn→inspect→picc→live tap 200).
  V2  swap both: CARD_A→nucula, CARD_B→ACR. Runs: nucula verifies the burn
      (URL, counter rotation) ‖ ACR read battery on CARD_B, then (full)
      burns CARD_B.
  V3  swap both back: CARD_A→ACR, CARD_B→nucula. Runs: ACR wipes CARD_A +
      blank verify + uid stability ‖ nucula verifies CARD_B (full) or read
      battery (minimal). Optional flags: --with-negative (V1), --with-ro
      (V3): unauthenticated reads on the read-only recovery card.
  V4  close (full): CARD_B→ACR (CARD_A off first). Runs: wipe CARD_B +
      blank verify + divergence report + end-state summary.

Usage:
  python3 tools/hil/nucula_cycle.py --visit v1 [--variant full|minimal]
  python3 tools/hil/nucula_cycle.py --visit v2
  python3 tools/hil/nucula_cycle.py --status | --report
  python3 tools/hil/nucula_cycle.py --visit v1 --dry-run   # host/CI walk

Evidence: raw transcripts under --evidence-dir (default OUTSIDE the repo,
owner directive 2026-10-19: raw logs never go to GitHub); audit events
append to /tmp/bolty-audit.log; state in tools/hil/results/.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hil import BoltyCli, BoltyError, CardRegistry  # noqa: E402

CARD_A = "04c474fa967380"
CARD_B = "04455ffa967380"
CARD_RO = "043365fa967380"
ISSUER = "0" * 31 + "1"
BURN_URL = "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}"
COORDINATOR = "192.168.13.208:20408"
PLACE_ACR = "ref-acr1252"
PLACE_NUCULA = "nucula-c3"
NUCULA_READER_PIN = "Nucula"
UID_SETTLE_S = 2.0
UID_ROUNDS = 20
READ_ROUNDS = 5
COUNTER_ROUNDS = 3
STATE_PATH = Path(__file__).resolve().parent / "results" / "nucula_cycle_state.json"
AUDIT_PATH = Path("/tmp/bolty-audit.log")
EVIDENCE_DEFAULT = Path("/root/bench-evidence/nucula-cycle")
VISITS = ["v1", "v2", "v3", "v4"]


class GateError(RuntimeError):
    """Raised when the coupled card fails the UID/registry gate."""


class Abort(RuntimeError):
    """Raised when a batch step failed; the run must stop before further ops."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def acr_cli() -> BoltyCli:
    return BoltyCli()


def nucula_cli() -> BoltyCli:
    return BoltyCli(reader=NUCULA_READER_PIN)


def _audit(line: str) -> None:
    entry = f"[{int(time.time() * 1000)}] EVENT nucula-cycle: {line}"
    print(entry)
    try:
        with open(AUDIT_PATH, "a") as f:
            f.write(entry + "\n")
    except OSError:
        pass


class Cycle:
    """Visit state + transcript writer + gated batches."""

    def __init__(self, evidence_dir: Path, dry_run: bool = False,
                 variant: str = "full", place_wait_min: int = 15):
        self.evidence_dir = evidence_dir
        self.dry_run = dry_run
        self.variant = variant
        self.place_wait_min = place_wait_min
        self.registry = CardRegistry()
        self.state = self._load_state()
        self._log_lines: list[str] = []

    def _load_state(self) -> dict:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
        return {"variant": self.variant, "visits_done": [], "snapshots": {}, "events": []}

    def save_state(self) -> None:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(self.state, indent=2))

    def log(self, msg: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        print(line)
        self._log_lines.append(line)

    def flush_transcript(self, name: str) -> Path:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        path = self.evidence_dir / f"{name}.log"
        with open(path, "a") as f:
            f.write("\n".join(self._log_lines) + "\n")
        self._log_lines = []
        return path

    def snapshot(self, uid: str, reader: str, **obs) -> None:
        obs.update({"ts": now(), "reader": reader, "uid": uid})
        self.state["snapshots"].setdefault(uid, []).append(obs)
        self.save_state()

    def visit_done(self, visit: str) -> None:
        if visit not in self.state["visits_done"]:
            self.state["visits_done"].append(visit)
        self.state["events"].append({"ts": now(), "event": f"visit {visit} complete"})
        self.save_state()

    def require_visits(self, *needed: str) -> None:
        missing = [v for v in needed if v not in self.state["visits_done"]]
        if missing:
            raise Abort(f"visits {missing} not done yet — run them first "
                        f"(done: {self.state['visits_done']})")

    # ── gating ─────────────────────────────────────────────────────────

    def gate(self, cli: BoltyCli, uid: str, op: str, reader: str) -> None:
        """UID + registry gate: runs BEFORE any mutating batch step."""
        self.registry.require(uid, op)
        time.sleep(0 if self.dry_run else UID_SETTLE_S)
        try:
            actual = cli.uid()
        except BoltyError as e:
            raise GateError(f"{reader}: no card coupled / uid read failed "
                            f"({str(e)[:120]}) — ABORT before mutation") from e
        if actual != uid:
            raise GateError(
                f"{reader}: expected {uid} coupled, found {actual or 'none'} — "
                f"ABORT before mutation. Move the right card, rerun this visit."
            )
        self.log(f"gate OK: {reader} carries {uid} (op={op})")

    # ── batches ────────────────────────────────────────────────────────

    def read_battery(self, cli: BoltyCli, uid: str, reader: str,
                     uid_rounds: int = UID_ROUNDS, read_rounds: int = READ_ROUNDS,
                     expect_url: bool = True) -> None:
        self.gate(cli, uid, "read", reader)
        bad = [(i, u) for i in range(uid_rounds)
               if (u := cli.uid()) != uid]
        if bad:
            raise Abort(f"{reader}: {len(bad)}/{uid_rounds} uid reads unstable: {bad[:3]}")
        nonempty = 0
        for _ in range(read_rounds):
            try:
                if "http" in cli.run("url", timeout_s=30):
                    nonempty += 1
            except BoltyError:
                if expect_url:
                    raise
        self.log(f"{reader}: uid {uid_rounds}/{uid_rounds} stable, "
                  f"url {nonempty}/{read_rounds} readable (expect_url={expect_url})")
        self.snapshot(uid, reader, kind="read_battery", uid_stable=True, url_ok=nonempty)
        if expect_url and nonempty == 0:
            raise Abort(f"{reader}: url never readable on {uid}")

    def burn_vertical(self, cli: BoltyCli, uid: str, reader: str) -> dict:
        self.gate(cli, uid, "burn", reader)
        burn = cli.run("burn", "--issuer-key", ISSUER, "--url", BURN_URL,
                       "--version", "1", "--confirm-uid", uid, timeout_s=120)
        if "burn complete" not in burn.lower():
            raise Abort(f"{reader}: burn did not complete on {uid}: {burn[-300:]}")
        insp = cli.run("inspect", "--issuer-key", ISSUER, "--verbose", timeout_s=60)
        if "PROVISIONED" not in insp.upper():
            raise Abort(f"{reader}: inspect not PROVISIONED after burn: {insp[-300:]}")
        return self.picc_and_tap(cli, uid, reader)

    def picc_and_tap(self, cli: BoltyCli, uid: str, reader: str) -> dict:
        picc = cli.run("picc", "--issuer-key", ISSUER, timeout_s=60)
        if "sdm verification passed" not in picc.lower():
            raise Abort(f"{reader}: picc did not verify on {uid}: {picc[-300:]}")
        counter = self._parse_counter(picc)
        m_p = re.search(r"p=([0-9A-Fa-f]{32})", picc)
        m_c = re.search(r"c=([0-9A-Fa-f]{16})", picc)
        tap_code = "200"
        if m_p and m_c and not self.dry_run:
            tap_url = f"{BURN_URL.split('?')[0]}?p={m_p.group(1)}&c={m_c.group(1)}"
            tap_code = self._curl_code(tap_url)
        if tap_code != "200":
            raise Abort(f"{reader}: worker tap HTTP {tap_code} (expected 200)")
        self.log(f"{reader}: picc verified, counter={counter}, tap {tap_code}")
        self.snapshot(uid, reader, kind="picc", counter=counter, tap=tap_code)
        return {"counter": counter}

    def counter_rotation(self, cli: BoltyCli, uid: str, reader: str) -> list[int]:
        counters = []
        for _ in range(COUNTER_ROUNDS):
            picc = cli.run("picc", "--issuer-key", ISSUER, timeout_s=60)
            counters.append(self._parse_counter(picc))
        if any(later <= earlier for earlier, later in zip(counters, counters[1:])):
            raise Abort(f"{reader}: SDM counter not rotating on {uid}: {counters}")
        self.log(f"{reader}: counter rotation {counters}")
        self.snapshot(uid, reader, kind="counter_rotation", counters=counters)
        return counters

    def wipe_blank(self, cli: BoltyCli, uid: str, reader: str) -> None:
        self.gate(cli, uid, "wipe", reader)
        cli.run("wipe", "--issuer-key", ISSUER, "--confirm-uid", uid, timeout_s=120)
        diag = cli.run("diagnose", "--issuer-key", ISSUER, timeout_s=60)
        if "BLANK" not in diag.upper():
            raise Abort(f"{reader}: card not BLANK after wipe: {diag[-300:]}")
        self.log(f"{reader}: {uid} wiped, state=BLANK")
        self.snapshot(uid, reader, kind="wipe", state="blank")

    def negative_probe(self, cli: BoltyCli, reader: str) -> None:
        """Non-NTAG card (e.g. J3R180) must fail honestly — no zeros lie."""
        time.sleep(0 if self.dry_run else UID_SETTLE_S)
        try:
            uid = cli.uid()
        except BoltyError:
            uid = ""
        zeros = uid.strip("0") == "" and uid != ""
        if uid in self.registry.uids_allowing("read"):
            raise Abort(f"{reader}: registered card {uid} coupled — "
                        "negative probe needs the J3R180, remove the NTAG")
        self.log(f"negative probe: uid={uid or '(error)'} "
                 f"{'ALL-ZEROS (silent-lie risk!)' if zeros else 'honest non-NTAG failure'}")
        self.snapshot(uid or "unknown", reader, kind="negative", zeros=zeros)

    def ro_battery(self, cli: BoltyCli, reader: str) -> None:
        """Read-only recovery card: UNAUTHENTICATED reads only, forever."""
        self.gate(cli, CARD_RO, "read", reader)
        stable = all(cli.uid() == CARD_RO for _ in range(READ_ROUNDS))
        if not stable:
            raise Abort(f"{reader}: {CARD_RO} uid unstable")
        self.log(f"{reader}: recovery card {CARD_RO} {READ_ROUNDS}/{READ_ROUNDS} stable (read-only)")
        self.snapshot(CARD_RO, reader, kind="ro_battery")

    @staticmethod
    def _parse_counter(picc_out: str) -> int:
        m = re.search(r"counter:\s*(\d+)", picc_out, re.I)
        if not m:
            raise Abort(f"no counter in picc output: {picc_out[-200:]}")
        return int(m.group(1))

    @staticmethod
    def _curl_code(url: str) -> str:
        try:
            p = subprocess.run(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "20", url],
                capture_output=True, text=True, timeout=30,
            )
            return p.stdout.strip()
        except subprocess.TimeoutExpired:
            return "timeout"

    # ── divergence report ──────────────────────────────────────────────

    def divergence_report(self) -> list[str]:
        findings: list[str] = []
        for uid, obs_list in self.state["snapshots"].items():
            uids = {o.get("uid") for o in obs_list}
            if len(uids) > 1:
                findings.append(f"{uid}: UID disagreement across observations: {uids}")
            merged = sorted(
                (o for o in obs_list if o.get("counter") is not None),
                key=lambda o: o["ts"],
            )
            counters = [o["counter"] for o in merged]
            if any(later < earlier for earlier, later in zip(counters, counters[1:])):
                findings.append(f"{uid}: counter went BACKWARDS across readers: {counters}")
        readers = {o.get("reader") for obs in self.state["snapshots"].values() for o in obs}
        self.log(f"divergence: {'CLEAN' if not findings else f'{len(findings)} finding(s)'} "
                 f"(cards observed: {sorted(self.state['snapshots'])}, readers: {sorted(readers)})")
        for f in findings:
            self.log(f"DIVERGENCE: {f}")
        return findings


# ── labgrid place guard (per batch; contention-aware) ─────────────────

@contextmanager
def place_guard(cycle: Cycle, place_name: str):
    if cycle.dry_run:
        yield
        return
    deadline = time.monotonic() + cycle.place_wait_min * 60
    attempt = 0
    while True:
        r = subprocess.run(
            ["labgrid-client", "-x", COORDINATOR, "-p", place_name, "acquire"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            _audit(f"acquired place {place_name}")
            break
        err = (r.stderr or r.stdout).strip()
        contended = "Failed to acquire resources" in err
        if not contended or time.monotonic() > deadline:
            raise Abort(f"could not acquire {place_name}: {err[:200]}")
        attempt += 1
        wait = min(5 * attempt, 30)
        print(f"[place] {place_name} contended ({err[:80]}); retry {attempt} in {wait}s")
        time.sleep(wait)
    try:
        yield
    finally:
        subprocess.run(
            ["labgrid-client", "-x", COORDINATOR, "-p", place_name, "release"],
            capture_output=True, timeout=30,
        )
        _audit(f"released place {place_name}")


@contextmanager
def bench_lock(cycle: Cycle):
    if cycle.dry_run:
        yield None
        return
    try:
        from tollgate_lab import acquire_bench_lock
    except ImportError as e:
        raise Abort("tollgate-lab missing — refusing hardware with degraded "
                    "exclusivity (bolty-rs #85)") from e
    lock = acquire_bench_lock("amperstrand-bench", project="nucula-cycle")
    try:
        yield lock
    finally:
        lock.release()


# ── visits ─────────────────────────────────────────────────────────────

def visit_v1(cycle: Cycle, args) -> None:
    a, n = acr_cli(), nucula_cli()
    if args.with_negative:
        with place_guard(cycle, PLACE_NUCULA):
            cycle.negative_probe(n, "nucula")
    with place_guard(cycle, PLACE_NUCULA):
        cycle.read_battery(n, CARD_B, "nucula")
    with place_guard(cycle, PLACE_ACR):
        cycle.read_battery(a, CARD_A, "acr", uid_rounds=5, read_rounds=2)
        cycle.burn_vertical(a, CARD_A, "acr")
    cycle.visit_done("v1")
    cycle.log("NEXT OWNER MOVE (V2): 04c474fa967380 ACR→nucula antenna, "
              "04455ffa967380 nucula→ACR antenna, then: --visit v2")


def visit_v2(cycle: Cycle, args) -> None:
    cycle.require_visits("v1")
    a, n = acr_cli(), nucula_cli()
    with place_guard(cycle, PLACE_NUCULA):
        cycle.gate(n, CARD_A, "read", "nucula")
        cycle.read_battery(n, CARD_A, "nucula", uid_rounds=5, read_rounds=2)
        cycle.counter_rotation(n, CARD_A, "nucula")
    with place_guard(cycle, PLACE_ACR):
        cycle.read_battery(a, CARD_B, "acr", uid_rounds=5, read_rounds=2)
        if cycle.variant == "full":
            cycle.burn_vertical(a, CARD_B, "acr")
    cycle.visit_done("v2")
    cycle.log("NEXT OWNER MOVE (V3): 04c474fa967380 nucula→ACR, "
              "04455ffa967380 ACR→nucula, then: --visit v3"
              + (" --with-ro" if args.with_ro else ""))


def visit_v3(cycle: Cycle, args) -> None:
    cycle.require_visits("v1", "v2")
    a, n = acr_cli(), nucula_cli()
    with place_guard(cycle, PLACE_ACR):
        cycle.wipe_blank(a, CARD_A, "acr")
        cycle.read_battery(a, CARD_A, "acr", uid_rounds=5, read_rounds=1, expect_url=False)
    with place_guard(cycle, PLACE_NUCULA):
        if args.with_ro:
            cycle.ro_battery(n, "nucula")
        if cycle.variant == "full":
            cycle.gate(n, CARD_B, "read", "nucula")
            cycle.counter_rotation(n, CARD_B, "nucula")
        else:
            cycle.read_battery(n, CARD_B, "nucula", uid_rounds=5, read_rounds=2)
    cycle.visit_done("v3")
    if cycle.variant == "full":
        cycle.log("NEXT OWNER MOVE (V4): 04c474fa967380 off the ACR → desk; "
                  "04455ffa967380 nucula→ACR, then: --visit v4")
    else:
        findings = cycle.divergence_report()
        cycle.log(f"MINIMAL CYCLE COMPLETE — divergence findings: {len(findings)}")


def visit_v4(cycle: Cycle, args) -> None:
    cycle.require_visits("v1", "v2", "v3")
    if cycle.variant != "full":
        raise Abort("v4 exists only in the full variant")
    a = acr_cli()
    with place_guard(cycle, PLACE_ACR):
        cycle.wipe_blank(a, CARD_B, "acr")
        cycle.read_battery(a, CARD_B, "acr", uid_rounds=5, read_rounds=1, expect_url=False)
    findings = cycle.divergence_report()
    cycle.visit_done("v4")
    cycle.log(f"FULL CYCLE COMPLETE — divergence findings: {len(findings)}; "
              "return cards to documented homes (04c474 may stay on the ACR)")


def next_move_hint(cycle: Cycle) -> str:
    done = cycle.state["visits_done"]
    hints = {
        "v1": "run --visit v1 after placing 04455ffa967380 on the nucula "
              "antenna and 04c474fa967380 on the ACR",
        "v2": "swap: 04c474fa967380 ACR→nucula, 04455ffa967380 nucula→ACR, then --visit v2",
        "v3": "swap back: 04c474fa967380 nucula→ACR, 04455ffa967380 ACR→nucula, then --visit v3",
        "v4": "04c474fa967380 off the ACR; 04455ffa967380 nucula→ACR, then --visit v4",
    }
    for v in VISITS:
        if v not in done:
            if v == "v4" and cycle.state.get("variant") == "minimal":
                return "cycle complete (minimal variant)"
            return f"NEXT: {hints[v]}"
    return "cycle complete"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--visit", choices=VISITS)
    ap.add_argument("--variant", choices=["full", "minimal"], default="full")
    ap.add_argument("--with-negative", action="store_true",
                    help="V1: J3R180 negative probe on the nucula first")
    ap.add_argument("--with-ro", action="store_true",
                    help="V3: unauthenticated read-only pass on 043365fa967380")
    ap.add_argument("--dry-run", action="store_true", help="no hardware, canned reader output")
    ap.add_argument("--reset", action="store_true", help="clear cycle state first")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--evidence-dir", type=Path, default=EVIDENCE_DEFAULT)
    ap.add_argument("--place-wait-min", type=int, default=15)
    args = ap.parse_args()

    cycle = Cycle(args.evidence_dir, dry_run=args.dry_run,
                  variant=args.variant, place_wait_min=args.place_wait_min)
    if args.reset:
        cycle.state = {"variant": args.variant, "visits_done": [], "snapshots": {}, "events": []}
        cycle.save_state()
        print("state reset")
    cycle.state["variant"] = args.variant

    if args.status:
        print(json.dumps(cycle.state, indent=2))
        print(next_move_hint(cycle))
        return 0
    if args.report:
        cycle.divergence_report()
        cycle.flush_transcript("report")
        print(next_move_hint(cycle))
        return 0
    if not args.visit:
        print(next_move_hint(cycle))
        return 0

    runner = {"v1": visit_v1, "v2": visit_v2, "v3": visit_v3, "v4": visit_v4}[args.visit]
    try:
        if args.dry_run:
            _install_dry_run_fakes(cycle)
            runner(cycle, args)
        else:
            with bench_lock(cycle):
                runner(cycle, args)
        cycle.flush_transcript(args.visit)
        return 0
    except (GateError, Abort) as e:
        cycle.log(f"ABORT: {e}")
        cycle.flush_transcript(args.visit)
        _audit(f"visit {args.visit} ABORTED: {e}")
        return 2
    except BoltyError as e:
        cycle.log(f"BOLTY-CLI ERROR: {e}")
        cycle.flush_transcript(args.visit)
        _audit(f"visit {args.visit} bolty-cli error: {e}")
        return 3


def _install_dry_run_fakes(cycle: Cycle) -> None:
    """Canned reader outputs so the full visit walk runs on host/CI.
    Each fake reader carries a mutable uid box; the patched gate simulates
    the owner's card move by setting the box to the expected UID."""

    class FakeCli(BoltyCli):
        def __init__(self, reader: str | None = None):
            super().__init__(reader=reader)
            self.uid_box = [""]
            self.calls: list[str] = []
            self._ctr = [380]

        def run(self, *args: str, timeout_s: int | None = None) -> str:
            self.calls.append(" ".join(args))
            cmd = args[0]
            if cmd == "uid":
                return f"Connected to reader: fake\nUID: {self.uid_box[0]}"
            if cmd == "url":
                return "https://boltcardpoc.psbt.me/?p=FAKE&c=FAKE"
            if cmd == "burn":
                return "burn complete"
            if cmd == "inspect":
                return "Card state: PROVISIONED\nK0 auth: SUCCESS"
            if cmd == "picc":
                self._ctr[0] += 1
                return (f"UID matches: YES\nRead counter: {self._ctr[0]}\n"
                        "p=" + "A" * 32 + "\nc=" + "B" * 16 +
                        "\nSDM verification PASSED")
            if cmd == "wipe":
                return "wipe complete"
            if cmd == "diagnose":
                return "Card state: BLANK"
            raise AssertionError(f"unexpected cmd {cmd}")

        def uid(self, retries: int = 1) -> str:
            self.calls.append("uid")
            return self.uid_box[0]

    fakes = {"acr": FakeCli(), "nucula": FakeCli(reader=NUCULA_READER_PIN)}
    for fake in fakes.values():
        fake.uid_box[0] = CARD_A if fake is fakes["acr"] else CARD_B

    global acr_cli, nucula_cli
    acr_cli = (lambda: fakes["acr"])
    nucula_cli = (lambda: fakes["nucula"])

    real_gate = Cycle.gate

    def gated(self, cli: BoltyCli, uid: str, op: str, reader: str) -> None:
        cli.uid_box[0] = uid
        real_gate(self, cli, uid, op, reader)

    Cycle.gate = gated


if __name__ == "__main__":
    sys.exit(main())
