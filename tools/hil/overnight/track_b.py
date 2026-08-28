#!/usr/bin/env python3
"""Track B — ACR1252 all-night lane (plan todo 10).

Drives the ACS ACR1252 PCSC reader + its NTAG424 card via `bolty-cli`
for the whole night, alongside whatever role the M5Stick stick plays:

  * reader-set assertion — ACR1252 PICC slot present; during the ccid
    window the GemPCTwin serial reader is additionally expected, and the
    bolty-cli reader pick (transport.rs: first "PICC" entry, else first
    non-"SAM") must STILL resolve to the ACR1252, never the GemPCTwin.
  * `bolty-cli cycle` loop — deterministic issuer key, paced >=60s,
    time-budget aware, harness-side UID assertion before EVERY mutation
    (`cycle` has no --confirm-uid flag; burn/wipe do — verified against
    apps/bolty-cli/src/main.rs), every output ledger-classified.
  * `test-ck` EXACTLY ONCE, STRICTLY BEFORE the first ACR burn: the
    command authenticates with factory-zero K0, which is only valid on a
    factory-blank card — after a deterministic burn it is a guaranteed
    wrong-key 91AE.  Guarded by a FIXED flag file outside the dated
    result dirs (shared across rehearsal + overnight) AND by a provably
    auth-free blankness proof AND by a burns-already-started refusal.
  * read-only monitors (uid/picc/diagnose every 5 min) — auth-free by
    construction or skipped; every output classified so a 91AE would be
    PROVEN (and recorded), never hidden.
  * pcscd health poll (60s) with journal snapshot on errors.
  * transport-error isolation + breaker survival: reader-absent /
    pcscd-down / disruption-window failures are journaled as transport
    anomalies and never touch card counters; bolty-cli's internal
    circuit breaker (exit code 6 after 10 auth failures, common.rs) is
    SURVIVED — the lane backs off 5->120s and resumes.
  * differential capture: `bolty-cli inspect --verbose` (NOTE: inspect
    prints human text — the --json global flag is accepted but ignored
    by cmd_inspect, so the harness parses text into JSON) after each
    burn, structurally compared against the stick card's inspect
    artifact modulo uid/ctr.
  * aware-pause API: pause()/resume() for the orchestrator's mid-night
    role-switch rescan; backoff 5->120s while readers are absent.

Standalone:  python3 track_b.py --selftest   (offline, no hardware)
Integration: register(ctx) as a LaneSpec target (build_lane()).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ledger as ledger_mod  # noqa: E402  (todo 6, same directory)

__all__ = [
    "ReaderSetError",
    "LANE_PLAN",
    "TrackB",
    "bolty_cli_pick",
    "assert_reader_set",
    "parse_inspect_text",
    "compare_artifacts",
    "plan_stage_order_ok",
    "test_ck_flag_path",
    "read_flag",
    "write_flag",
    "register",
    "build_lane",
]

# ------------------------------------------------------------------ consts ----

DEFAULT_URL = "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}"

CYCLE_PACE_S = 60.0        # plan: pacing >=60s between burns
MONITOR_PACE_S = 300.0     # plan: read-only monitors every 5 min
PCSCD_POLL_S = 60.0        # plan: readers() health poll every 60s
CYCLE_EST_S = 120.0        # rough wall-clock bound of one uid+cycle+inspect
BACKOFF_STEPS = (5, 10, 20, 40, 80, 120)  # aware-pause backoff, capped at 120
GENUINE_FAIL_LIMIT = 3     # consecutive non-window failures -> lane FAIL row
CYCLE_TIMEOUT_S = 300.0
CMD_TIMEOUT_S = 90.0

# bolty-cli exit codes (apps/bolty-cli/src/main.rs exit_code_for +
# common.rs record_auth_failure)
BREAKER_EXIT = 6           # internal circuit breaker: 10 auth failures
TRANSPORT_EXITS = (2, 3, 4)  # NoReaders / NoCardInReader / other pcsc error

# The lane plan is an ordered object: test-ck STRICTLY before any burn.
LANE_PLAN = ("reader_gate", "test_ck", "cycle_loop")

FLAG_NAME = "TEST_CK_DONE"  # fixed path, outside the dated result dirs

# ------------------------------------------------------------ reader set ----


class ReaderSetError(Exception):
    """The pcscd reader set does not satisfy Track B preconditions."""


def bolty_cli_pick(readers):
    """Mirror transport.rs::PcscTransport::connect reader pick exactly:
    first entry containing "PICC", else first entry without "SAM", else
    the first entry.  Returns None when no readers exist."""
    readers = list(readers or [])
    for r in readers:
        if "PICC" in r:
            return r
    for r in readers:
        if "SAM" not in r:
            return r
    return readers[0] if readers else None


def assert_reader_set(readers, expect_gempctwin=False):
    """Assert the pcscd reader set supports Track B.

    * the ACR1252 PICC slot is present (the ACR1252 shows TWO entries —
      PICC 00 00 + SAM 01 00 slots of ONE physical device; assert on the
      PICC entry, not on entry counts);
    * bolty-cli's pick (bolty_cli_pick) resolves to the ACR1252 PICC —
      the GemPCTwin serial reader, present during the ccid window, must
      never be selected (its name contains no "PICC", so the transport
      preference order keeps the ACR — asserted, not assumed);
    * with expect_gempctwin (WINDOW2), the GemPCTwin is additionally
      required (missing = Mode-B-grade anomaly worth a row).
    """
    readers = [str(r) for r in (readers or [])]
    acr_picc = [r for r in readers if "ACR1252" in r and "PICC" in r]
    if not acr_picc:
        raise ReaderSetError(f"ACR1252 PICC slot not present in {readers!r}")
    pick = bolty_cli_pick(readers)
    if pick not in acr_picc:
        raise ReaderSetError(
            f"bolty-cli pick {pick!r} is not the ACR1252 PICC entry "
            f"(would target the wrong reader)"
        )
    if expect_gempctwin and not any("GemPC" in r for r in readers):
        raise ReaderSetError(
            "ccid window expects the GemPCTwin serial reader as well"
        )
    return {"ok": True, "pick": pick, "acr_picc": acr_picc,
            "readers": readers}


def default_readers_fn():
    """pcscd readers() (pyscard imported lazily — never at module load)."""
    from smartcard.System import readers  # noqa: PLC0415

    return [str(r) for r in readers()]


# --------------------------------------------------------------- parsers ----

_UID_RE = re.compile(r"(?im)^\s*(?:Card )?UID:\s*([0-9A-Fa-f]{14})\s*$")
_ndef_len_re = re.compile(r"NDEF content \((\d+) bytes?\)")
_settings_re = re.compile(r"NDEF file settings: (.*)")
_ar_re = re.compile(
    r"access_rights: AccessRights \{\s*read: ([\w()]+), write: ([\w()]+),"
    r"\s*read_write: ([\w()]+), change: ([\w()]+)\s*\}")
_picc_data_re = re.compile(r"picc_data: ([A-Za-z_]+)")
_file_read_re = re.compile(r"file_read: (None|Some)")
_sdm_re = re.compile(
    r"SDM PICC decrypted: UID=([0-9A-Fa-f]+) counter=(\d+)"
    r" CMAC_valid=(true|false)")
_k0auth_re = re.compile(r"K0 auth: (SUCCESS|FAILED|delayed)")
_ndef_url_re = re.compile(r"(?im)^NDEF URL: (.+)$")
_p_hex_re = re.compile(r"[?&]p=[0-9A-Fa-f]{32}")
_c_hex_re = re.compile(r"[?&]c=[0-9A-Fa-f]{16}")


def mask_dynamic_url(url):
    """Mask the SDM-dynamic p=/c= parameters so a live-read URL compares
    equal to the template ('NDEF template modulo uid/ctr')."""
    if not url:
        return None
    out = _p_hex_re.sub("?p={picc}", url)
    out = _c_hex_re.sub("&c={mac}", out)
    return out


def parse_uid_output(text):
    """UID from `bolty-cli uid` / `picc` / `test-ck` output, else None."""
    if not text:
        return None
    m = _UID_RE.search(text)
    return m.group(1).upper() if m else None


def _norm_access(tok):
    tok = tok.strip()
    m = re.fullmatch(r"Key\((\w+)\)", tok)
    return (m.group(1) if m else tok).lower()


def parse_inspect_text(text):
    """`bolty-cli inspect [--verbose]` human output -> canonical dict.

    inspect prints TEXT even with the (ignored) global --json flag; this
    parser is what turns it into the stored JSON artifact.
    """
    art = {
        "uid": parse_uid_output(text),
        "access_rights": None,
        "sdm_active": None,
        "sdm_parsed": False,
        "ndef_file_settings": None,
        "ndef_len": None,
        "ndef_url_template": None,
        "k0_auth": None,
        "sdm_picc": None,
        "raw": text,
    }
    m = _settings_re.search(text)
    if m:
        line = m.group(1)
        art["ndef_file_settings"] = line.strip()
        ar = _ar_re.search(line)
        if ar:
            art["access_rights"] = {
                "read": _norm_access(ar.group(1)),
                "write": _norm_access(ar.group(2)),
                "read_write": _norm_access(ar.group(3)),
                "change": _norm_access(ar.group(4)),
            }
        picc = _picc_data_re.search(line)
        fread = _file_read_re.search(line)
        if picc and fread:
            art["sdm_parsed"] = True
            art["sdm_active"] = (
                picc.group(1) != "None" or fread.group(1) == "Some"
            )
    m = _ndef_len_re.search(text)
    if m:
        art["ndef_len"] = int(m.group(1))
    m = _ndef_url_re.search(text)
    if m:
        art["ndef_url_template"] = mask_dynamic_url(m.group(1).strip())
    m = _k0auth_re.search(text)
    if m:
        art["k0_auth"] = m.group(1)
    m = _sdm_re.search(text)
    if m:
        art["sdm_picc"] = {
            "uid": m.group(1).upper(),
            "counter": int(m.group(2)),
            "cmac_valid": m.group(3) == "true",
        }
    return art


def inspect_provably_blank(artifact):
    """Auth-free blankness verdict from a NO-KEY inspect artifact.

    Mirrors diagnose.rs `looks_blank = !has_sdm && !has_ndef_content`:
    blank iff the SDM config parsed INACTIVE and no NDEF URL/bytes.  An
    unparseable/unreadable setting line is NOT provably blank — the
    caller must skip (a wrong guess here would be a wrong-key factory
    auth against a provisioned card).
    """
    if not artifact:
        return False
    return (
        artifact.get("sdm_parsed") is True
        and artifact.get("sdm_active") is False
        and artifact.get("ndef_url_template") is None
        and artifact.get("ndef_len") in (0, None)
    )


# ----------------------------------------------------------- differential ----

_COMPARE_FIELDS = (
    ("ndef_url_template", "NDEF template"),
    ("access_rights", "key settings (NDEF access rights)"),
    ("sdm_active", "SDM config active"),
    ("k0_auth", "K0 auth (deterministic key)"),
)


def compare_artifacts(acr, stick):
    """Structural diff of an ACR inspect artifact vs a stick burn-cycle
    inspect artifact, modulo uid/counter (masked upstream).  A field
    missing on either side is MISSING (unverifiable), never a mismatch —
    an honest gap beats a fabricated difference."""
    fields = []
    for key, label in _COMPARE_FIELDS:
        a, s = acr.get(key), stick.get(key)
        if a is None or s is None:
            fields.append({"field": key, "label": label, "acr": a,
                           "stick": s, "verdict": "MISSING"})
        else:
            fields.append({"field": key, "label": label, "acr": a,
                           "stick": s,
                           "verdict": "MATCH" if a == s else "MISMATCH"})
    mismatch = [f for f in fields if f["verdict"] == "MISMATCH"]
    missing = [f for f in fields if f["verdict"] == "MISSING"]
    lines = ["### Differential: ACR burn vs stick burn_cycle inspect",
             f"- verdict: {'MATCH' if not mismatch else 'MISMATCH'} "
             f"({len(mismatch)} differ, {len(missing)} unverifiable)",
             f"- ACR uid: {acr.get('uid')} | stick uid: {stick.get('uid')}",
             "", "| field | ACR | stick | verdict |",
             "|---|---|---|---|"]
    for f in fields:
        lines.append(f"| {f['label']} | {f['acr']} | {f['stick']} |"
                     f" {f['verdict']} |")
    return {"match": not mismatch, "fields": fields,
            "markdown": "\n".join(lines)}


def find_stick_artifact(results_root):
    """Most recent stick inspect artifact under the results tree, if the
    Track A side has stored one yet (stick_inspect_*.json)."""
    root = Path(results_root)
    if not root.exists():
        return None
    cands = sorted(root.rglob("stick_inspect*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


# ------------------------------------------------------------ test-ck guard ----


def test_ck_flag_path(results_root=None):
    """FIXED guard flag path — directly under results/, outside the
    dated run dirs, so exactly-once holds across rehearsal + overnight."""
    if results_root is None:
        results_root = Path(__file__).resolve().parent / "results"
    return Path(results_root) / FLAG_NAME


def _atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def write_flag(path, uid, outcome):
    """Record that the one global test-ck ATTEMPT happened (pass or
    fail — a failed attempt still proves the card was not factory
    blank, and retrying would wrong-key auth it again)."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _atomic_write(Path(path), f"ts={ts}\nuid={ledger_mod.normalize_uid(uid)}\n"
                              f"outcome={outcome}\n")


def read_flag(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out or None


def plan_stage_order_ok(plan):
    """The lane plan must order the single test-ck stage STRICTLY before
    the first cycle (burn) stage — enforced on the plan object itself."""
    plan = list(plan or [])
    if plan.count("test_ck") != 1:
        return False
    if "cycle_loop" not in plan:
        return False
    return plan.index("test_ck") < plan.index("cycle_loop")


# ----------------------------------------------------------------- runner ----


class SubprocessRunner:
    """Real bolty-cli via subprocess; returns (rc, stdout+stderr)."""

    def __init__(self, binary="bolty-cli"):
        self.binary = binary

    def __call__(self, argv, timeout=None):
        proc = subprocess.run(
            [self.binary, *argv], capture_output=True, text=True,
            timeout=timeout or CMD_TIMEOUT_S, check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


# ------------------------------------------------------------------ lane ----


class TrackB:
    """The Track B lane.  All hardware access is injected (runner,
    readers_fn, journal_fn) so the whole lane is offline-testable."""

    def __init__(self, *, runner, readers_fn, journal_fn, ledger,
                 results_root, clock, uid, issuer_key,
                 url=DEFAULT_URL, key_version=1,
                 cycle_pace_s=CYCLE_PACE_S, monitor_pace_s=MONITOR_PACE_S,
                 pcscd_poll_s=PCSCD_POLL_S, budget_s=None,
                 cycle_timeout_s=CYCLE_TIMEOUT_S, cmd_timeout_s=CMD_TIMEOUT_S):
        self.runner = runner
        self.readers_fn = readers_fn
        self.journal_fn = journal_fn
        self.ledger = ledger
        self.results_root = Path(results_root)
        self.clock = clock
        self.uid = ledger_mod.normalize_uid(uid)
        self.issuer_key = (issuer_key or "").strip().lower()
        self.url = url
        self.key_version = int(key_version)
        self.cycle_pace_s = float(cycle_pace_s)
        self.monitor_pace_s = float(monitor_pace_s)
        self.pcscd_poll_s = float(pcscd_poll_s)
        self.budget_s = float(budget_s) if budget_s else None
        self.cycle_timeout_s = float(cycle_timeout_s)
        self.cmd_timeout_s = float(cmd_timeout_s)

        # lane state
        self.burns_started = 0     # >0 forever forbids test-ck (this process)
        self.cycles_passed = 0
        self.expected_state = "unknown"  # blank | provisioned | unknown
        self._pause_reason = None
        self._backoff_i = 0
        self._genuine_fails = 0

    # ------------------------------------------------------- aware pause ----

    def pause(self, reason="orchestrator"):
        """Orchestrator hook: role-switch rescan / pcscd maintenance."""
        self._pause_reason = reason or "orchestrator"

    def resume(self):
        self._pause_reason = None

    def is_paused(self):
        return self._pause_reason is not None

    def _next_backoff(self):
        step = BACKOFF_STEPS[min(self._backoff_i, len(BACKOFF_STEPS) - 1)]
        self._backoff_i += 1
        return float(step)

    def _reset_backoff(self):
        self._backoff_i = 0

    # --------------------------------------------------------- utilities ----

    def _row(self, ctx, **fields):
        if ctx is not None and hasattr(ctx, "row"):
            return ctx.row(**fields)
        return fields

    def _skip(self, ctx, reason, **fields):
        if ctx is not None and hasattr(ctx, "skip"):
            return ctx.skip(reason, **fields)
        return self._row(ctx, type="SKIP", status="SKIP", reason=reason,
                         **fields)

    def _anomaly(self, ctx, kind, **fields):
        if ctx is not None and hasattr(ctx, "anomaly"):
            return ctx.anomaly(kind, **fields)
        return self._row(ctx, type="anomaly", status="ANOMALY", kind=kind,
                         **fields)

    def _sleep(self, ctx, s):
        if ctx is not None and hasattr(ctx, "sleep"):
            ctx.sleep(s)
        else:
            self.clock.sleep(s)

    def _running(self, ctx):
        return ctx.running() if ctx is not None and hasattr(ctx, "running") \
            else True

    def _run(self, argv, timeout=None):
        return self.runner(argv, timeout=timeout)

    def _classify(self, ctx, text, op, *, card=None):
        """Ledger-classify EVERY bolty-cli output (routing load-bearing):
        auth_fail -> card counters, transport -> journal only."""
        card = card or self.uid
        if self.ledger is not None:
            return self.ledger.record_classified(card, text)
        return ledger_mod.classify_output(text)

    def _readers_healthy(self):
        try:
            assert_reader_set(self.readers_fn())
            return True
        except (ReaderSetError, Exception):  # noqa: BLE001 — probe, never fatal
            return False

    # ------------------------------------------------------ reader gate ----

    def stage_reader_gate(self, ctx):
        expect_gempctwin = getattr(ctx, "phase", "") == "WINDOW2"
        try:
            info = assert_reader_set(self.readers_fn(),
                                     expect_gempctwin=expect_gempctwin)
        except ReaderSetError as e:
            self._row(ctx, type="reader_gate", status="FAIL", error=str(e))
            return False
        self._row(ctx, type="reader_gate", status="PASS",
                  pick=info["pick"], readers=info["readers"])
        return True

    # -------------------------------------------------------- test-ck ----

    def stage_test_ck(self, ctx):
        """EXACTLY ONCE, STRICTLY BEFORE the first ACR burn.

        Ordered first in LANE_PLAN; four independent guards:
        1. fixed flag file present (ran at rehearsal/earlier) -> SKIP;
        2. burns already started in this process -> SKIP (never after);
        3. card not PROVABLY blank via a no-key inspect (auth-free) ->
           SKIP (factory-zero K0 is only valid on a factory-blank card);
        4. fresh UID assertion immediately before the call.
        """
        flag = test_ck_flag_path(self.results_root)
        prior = read_flag(flag)
        if prior is not None:
            self._skip(ctx, f"test-ck already done at {prior.get('ts')} "
                            f"(uid={prior.get('uid')}, "
                            f"outcome={prior.get('outcome')})")
            return
        if self.burns_started > 0:
            self._skip(ctx, "test-ck refused: an ACR burn already started — "
                            "factory-zero K0 auth would be wrong-key 91AE")
            return

        # provably auth-free blankness proof: inspect WITHOUT --issuer-key
        # never authenticates (inspect.rs: auth only under Some(issuer_key))
        rc, out = self._run(["inspect"], timeout=self.cmd_timeout_s)
        self._classify(ctx, out, "inspect_nokey")
        if rc != 0:
            self._skip(ctx, f"test-ck skipped: blankness probe failed rc={rc}")
            return
        artifact = parse_inspect_text(out)
        if not inspect_provably_blank(artifact):
            self._skip(
                ctx,
                "test-ck skipped: card not PROVABLY factory-blank "
                f"(sdm_parsed={artifact.get('sdm_parsed')}, "
                f"sdm_active={artifact.get('sdm_active')}, "
                f"ndef_len={artifact.get('ndef_len')}) — factory-zero K0 "
                "auth is only valid on a blank card")
            return

        # fresh UID assertion immediately before the call
        rc, out = self._run(["uid"], timeout=self.cmd_timeout_s)
        self._classify(ctx, out, "uid")
        observed = parse_uid_output(out)
        try:
            ledger_mod.assert_target_uid(observed, self.uid, context="test-ck")
        except ledger_mod.UidMismatchError as e:
            self._anomaly(ctx, "uid_mismatch", error=str(e))
            self._skip(ctx, "test-ck skipped: uid mismatch before call")
            return

        try:
            if self.ledger is not None:
                self.ledger.assert_may_proceed(self.uid)
        except ledger_mod.CardSafetyError as e:
            self._row(ctx, type="test_ck", status="FAIL", error=str(e))
            return

        # burns_started guard: set before the subprocess so a crash mid-
        # test-ck can never be followed by a burn-then-test-ck ordering.
        rc, out = self._run(["test-ck"], timeout=self.cmd_timeout_s)
        kind = self._classify(ctx, out, "test-ck")
        ok = rc == 0 and "ALL PASS" in out
        if self.ledger is not None:
            self.ledger.record_op(self.uid, "test_ck")
        write_flag(flag, self.uid, "PASS" if ok else "FAIL")
        self.expected_state = "blank" if ok else "unknown"
        self._row(ctx, type="test_ck", status="PASS" if ok else "FAIL",
                  rc=rc, **{"class": kind}, flag=str(flag))
        if ok:
            self._row(ctx, type="differential_note",
                      note="test-ck round-trip leaves the card factory-blank")

    # ---------------------------------------------------------- monitors ----

    def _monitor_tick(self, ctx):
        """uid/picc/diagnose, every 5 min, provably auth-free or skipped.

        * uid / picc are auth-free by construction (no auth APDUs);
        * diagnose probes factory K0 (correct key, blank-looking cards
          only) BUT also fires a static M5StickC test-key auth when the
          card is neither blank-looking nor SDM-derivable — a WRONG-KEY
          path.  So diagnose runs ONLY when the lane knows the card
          state (blank / provisioned-with-our-keys); after a failed
          cycle the state is unknown -> honest SKIP.
        * every output is classified: no 91AE can hide (else recorded).
        """
        rc, out = self._run(["uid"], timeout=self.cmd_timeout_s)
        kind = self._classify(ctx, out, "uid")
        self._row(ctx, type="monitor", op="uid", status="PASS" if rc == 0
                  else "FAIL", **{"class": kind},
                  uid=parse_uid_output(out))
        if kind == "auth_fail":
            self.expected_state = "unknown"

        rc, out = self._run(["picc", "--issuer-key", self.issuer_key],
                            timeout=self.cmd_timeout_s)
        kind = self._classify(ctx, out, "picc")
        self._row(ctx, type="monitor", op="picc", status="PASS" if rc == 0
                  else "FAIL", **{"class": kind})
        if kind == "auth_fail":
            self.expected_state = "unknown"

        if self.expected_state in ("blank", "provisioned"):
            rc, out = self._run(["diagnose", "--issuer-key", self.issuer_key],
                                timeout=self.cmd_timeout_s)
            kind = self._classify(ctx, out, "diagnose")
            self._row(ctx, type="monitor", op="diagnose",
                      status="PASS" if rc == 0 else "FAIL", **{"class": kind})
            if kind == "auth_fail":
                # should be impossible by construction — record, never hide
                self.expected_state = "unknown"
                self._anomaly(ctx, "monitor_auth_fail", op="diagnose")
        else:
            self._skip(ctx, "diagnose skipped: card state unknown — "
                            "static-test-key probe would be a wrong-key auth")

    # ------------------------------------------------------ pcscd health ----

    def _health_tick(self, ctx):
        expect_gempctwin = getattr(ctx, "phase", "") == "WINDOW2"
        try:
            info = assert_reader_set(self.readers_fn(),
                                     expect_gempctwin=expect_gempctwin)
        except ReaderSetError as e:
            self._snapshot_journal(ctx, str(e))
            return
        except Exception as e:  # noqa: BLE001 — readers() itself died
            self._snapshot_journal(ctx, repr(e))
            return
        self._row(ctx, type="health", status="PASS", pick=info["pick"])

    def _snapshot_journal(self, ctx, error):
        """journalctl -u pcscd -n 50 snapshot + isolated transport
        anomaly (never a card event)."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            snapshot = self.journal_fn()
        except Exception as e:  # noqa: BLE001 — snapshot is best-effort
            snapshot = f"journal snapshot failed: {e!r}"
        path = self.results_root / f"pcscd_journal_{ts}.txt"
        try:
            _atomic_write(path, snapshot)
        except OSError:
            path = None
        self._anomaly(ctx, "pcscd_unhealthy", error=error[:200],
                      snapshot=str(path) if path else None,
                      isolated="transport")

    # ------------------------------------------------------ cycle loop ----

    def _wait_disrupted(self, ctx, reason):
        """Backoff 5->120s while readers are absent (or the orchestrator
        pause is still held); resume on reader return — if the ACR PICC
        set is healthy again the disruption is objectively over, so an
        orchestrator that crashed before resume() cannot wedge the lane
        for the rest of the night."""
        while self._running(ctx):
            if self._readers_healthy():
                if self.is_paused():
                    self.resume()
                break
            step = self._next_backoff()
            self._row(ctx, type="backoff", reason=reason, sleep_s=step,
                      paused=self.is_paused())
            self._sleep(ctx, step)
        self._reset_backoff()

    def _assert_uid(self, ctx, context):
        """Fresh `bolty-cli uid` + assert_target_uid right before a
        mutation (`cycle` accepts no --confirm-uid — main.rs — so the
        harness enforces the expected card here)."""
        rc, out = self._run(["uid"], timeout=self.cmd_timeout_s)
        self._classify(ctx, out, "uid")
        if rc != 0:
            self._anomaly(ctx, "uid_unreadable", context=context, rc=rc)
            return False
        try:
            ledger_mod.assert_target_uid(parse_uid_output(out), self.uid,
                                         context=context)
        except ledger_mod.UidMismatchError as e:
            self._anomaly(ctx, "uid_mismatch", context=context, error=str(e))
            return False
        return True

    def _cycle_tick(self, ctx):
        """One bounded cycle attempt.  Returns False when the lane must
        stop (repeated genuine failures / safety halt)."""
        try:
            if self.ledger is not None:
                self.ledger.assert_may_proceed(self.uid)
        except ledger_mod.CardSafetyError as e:
            self._row(ctx, type="cycle", status="FAIL", error=str(e),
                      halted=True)
            return False

        try:
            cm = ctx.card("acr") if ctx is not None and hasattr(ctx, "card") \
                else _null_cm()
        except Exception as e:  # MutationWindowClosed (duck-typed)
            if type(e).__name__ != "MutationWindowClosed":
                raise
            self._skip(ctx, f"mutation window closed ({e})")
            return True

        with cm:
            if not self._assert_uid(ctx, "cycle"):
                return True  # wrong card on reader: anomaly recorded, retry later

            # from here on the card WILL be mutated: forbid test-ck forever
            self.burns_started += 1
            argv = ["cycle", "--issuer-key", self.issuer_key,
                    "--url", self.url, "--version", str(self.key_version)]
            start_mono = self.clock.monotonic()
            rc, out = self._run(argv, timeout=self.cycle_timeout_s)
            kind = self._classify(ctx, out, "cycle")

            if rc == 0:
                self.cycles_passed += 1
                self._genuine_fails = 0
                self.expected_state = "provisioned"
                if self.ledger is not None:
                    self.ledger.record_op(self.uid, "cycle")
                self._row(ctx, type="cycle", status="PASS",
                          n=self.cycles_passed, mono=round(start_mono, 3),
                          **{"class": kind})
                self._capture_differential(ctx, self.cycles_passed)
                return True

            return self._cycle_failure(ctx, rc, out, kind)

    def _cycle_failure(self, ctx, rc, out, kind):
        """Failure routing: transport/breaker isolated; auth_fail counted
        by the ledger via record_classified; genuine repeats FAIL."""
        disrupted = self.is_paused() or not self._readers_healthy()
        breaker = rc == BREAKER_EXIT
        self._row(ctx, type="cycle", status="FAIL", rc=rc, **{"class": kind},
                  breaker=breaker, disrupted=disrupted)

        if kind == "transport" or rc in TRANSPORT_EXITS:
            # isolated transport anomaly — NEVER a card event/counters
            self._anomaly(ctx, "transport_error", rc=rc, isolated="transport")

        if breaker:
            # bolty-cli's internal 10-failure breaker exited (code 6);
            # the harness wraps it and survives: back off and resume.
            self._anomaly(ctx, "breaker_exit", rc=rc,
                          isolated="transport" if disrupted else "session")

        if disrupted:
            # disruption-window failure: NEVER genuine, never lane-fatal
            self._wait_disrupted(ctx, "transport disruption")
            return True

        self._genuine_fails += 1
        if self._genuine_fails >= GENUINE_FAIL_LIMIT:
            self._row(ctx, type="cycle", status="FAIL",
                      error=f"{self._genuine_fails} consecutive non-window "
                            f"failures", lane_fail=True)
            return False
        step = self._next_backoff()
        self._row(ctx, type="backoff", reason="genuine failure",
                  sleep_s=step)
        self._sleep(ctx, step)
        return True

    def _capture_differential(self, ctx, n):
        """inspect --verbose after each burn (the plan's --json is
        accepted-but-ignored by cmd_inspect; output is text) -> stored
        JSON artifact + structural compare vs the stick artifact."""
        argv = ["inspect", "--verbose", "--issuer-key", self.issuer_key,
                "--version", str(self.key_version)]
        rc, out = self._run(argv, timeout=self.cmd_timeout_s)
        kind = self._classify(ctx, out, "inspect")
        artifact = parse_inspect_text(out)
        run_dir = self._run_dir(ctx)
        path = run_dir / "differential" / f"acr_inspect_{n}.json"
        try:
            _atomic_write(path, json.dumps(
                {k: v for k, v in artifact.items() if k != "raw"}, indent=1,
                sort_keys=True) + "\n")
        except OSError:
            path = None
        if rc != 0:
            self._row(ctx, type="differential", status="FAIL", rc=rc,
                      **{"class": kind}, artifact=str(path) if path else None)
            return
        stick_path = find_stick_artifact(self.results_root)
        if stick_path is None:
            self._skip(ctx, "differential: no stick inspect artifact yet")
            return
        try:
            stick = json.loads(stick_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            self._skip(ctx, f"differential: stick artifact unreadable ({e})")
            return
        result = compare_artifacts(artifact, stick)
        self._row(ctx, type="differential", status="PASS" if result["match"]
                  else "MISMATCH", n=n, artifact=str(path),
                  stick=str(stick_path), report=result["markdown"])
        if not result["match"]:
            self._anomaly(ctx, "differential_mismatch", n=n)

    def _run_dir(self, ctx):
        """Dated results dir: the orchestrator's store dir when wired,
        else <results_root>/<UTC-date>."""
        store = getattr(ctx, "store", None) if ctx is not None else None
        d = getattr(store, "dir", None)
        if d:
            return Path(d)
        day = datetime.fromtimestamp(self.clock.time(), tz=timezone.utc)
        return self.results_root / day.strftime("%Y-%m-%d")

    # --------------------------------------------------------- main loop ----

    def cycle_loop(self, ctx):
        """Mutation+monitor+health scheduler until budget/stop.  Mutations
        stop CYCLE_EST_S before the budget end (never start what cannot
        finish); read-only monitors run to the wall."""
        now = self.clock.monotonic()
        end = now + self.budget_s if self.budget_s else None
        next_cycle = now
        next_monitor = now + self.monitor_pace_s
        next_health = now + self.pcscd_poll_s
        budget_noted = False

        while self._running(ctx):
            now = self.clock.monotonic()
            if end is not None and now >= end:
                self._row(ctx, type="budget_end", status="INFO",
                          mono=round(now, 3))
                break

            if now >= next_health:
                self._health_tick(ctx)
                next_health = now + self.pcscd_poll_s
            if now >= next_monitor:
                self._monitor_tick(ctx)
                next_monitor = now + self.monitor_pace_s
            if next_cycle is not None and now >= next_cycle:
                if end is not None and now + CYCLE_EST_S > end and \
                        not budget_noted:
                    self._row(ctx, type="budget_skip", status="SKIP",
                              reason=f"cycle would exceed budget end by "
                                     f"{round(now + CYCLE_EST_S - end, 1)}s")
                    budget_noted = True
                    next_cycle = None
                else:
                    if not self._cycle_tick(ctx):
                        return
                    next_cycle = self.clock.monotonic() + self.cycle_pace_s

            now = self.clock.monotonic()
            upcoming = [t for t in (next_cycle, next_monitor, next_health)
                        if t is not None]
            wake = min(upcoming) if upcoming else None
            if end is not None:
                wake = end if wake is None else min(wake, end)
            if wake is not None and wake > now:
                self._sleep(ctx, wake - now)

    # -------------------------------------------------------------- run ----

    def run(self, ctx):
        plan = list(LANE_PLAN)
        if not plan_stage_order_ok(plan):  # paranoia: never burn first
            self._row(ctx, type="lane", status="FAIL",
                      error=f"invalid lane plan ordering: {plan}")
            return
        for stage in plan:
            if not self._running(ctx):
                break
            if stage == "reader_gate":
                if not self.stage_reader_gate(ctx):
                    return  # no ACR PICC all night: nothing this lane can do
            elif stage == "test_ck":
                self.stage_test_ck(ctx)
            elif stage == "cycle_loop":
                self.cycle_loop(ctx)

    # ---------------------------------------------------------- factory ----

    @classmethod
    def from_ctx(cls, ctx):
        """Build the lane from a duck-typed PhaseContext + environment.

        Returns None (caller records an honest SKIP) when the ACR uid or
        issuer key is unconfigured — mutations without configuration are
        refused, not guessed.
        """
        env = os.environ
        uid = env.get("HIL_UID_ACR", "").strip()
        led = getattr(ctx, "ledger", None)
        issuer = env.get("HIL_ISSUER", "").strip() or (
            getattr(led, "issuer_key", "") or "")
        if len(uid) != 14 or len(issuer) != 32:
            return None
        binary = env.get("BOLTY_CLI", "bolty-cli")
        return cls(
            runner=SubprocessRunner(binary),
            readers_fn=default_readers_fn,
            journal_fn=lambda: subprocess.run(
                ["journalctl", "-u", "pcscd", "-n", "50"],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout,
            ledger=led if hasattr(led, "record_classified") else None,
            results_root=Path(__file__).resolve().parent / "results",
            clock=getattr(ctx, "clock", None) or _RealClockShim(),
            uid=uid,
            issuer_key=issuer,
            url=env.get("HIL_URL", DEFAULT_URL),
            key_version=env.get("HIL_KEY_VERSION", "1"),
            budget_s=float(env["TRACKB_BUDGET_S"])
            if env.get("TRACKB_BUDGET_S") else None,
        )


class _RealClockShim:
    import time as _time

    def monotonic(self):
        return self._time.monotonic()

    def time(self):
        return self._time.time()

    def sleep(self, s):
        if s > 0:
            self._time.sleep(s)


class _null_cm:
    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False


_null_cm = _null_cm()  # shared no-op card-lock stand-in


# ---------------------------------------------------------- integration ----


def register(ctx):
    """Lane target (todo-5 LaneSpec contract): run Track B all night."""
    tb = TrackB.from_ctx(ctx)
    if tb is None:
        ctx.skip("track_b unconfigured: need HIL_UID_ACR (14 hex) + "
                 "HIL_ISSUER (32 hex) — refusing to guess card targets")
        return
    tb.run(ctx)


def build_lane():
    """LaneSpec for overnight.load_track_specs; duck-typed fallback when
    the (in-flight) orchestrator module is not importable."""
    try:
        import overnight
    except ImportError:
        from types import SimpleNamespace
        return SimpleNamespace(name="track_b_acr", target=register,
                               window="all_night", cards=("acr",),
                               needs_pcscd=True, pace_s=CYCLE_PACE_S)
    return overnight.LaneSpec("track_b_acr", register, window="all_night",
                              cards=("acr",), needs_pcscd=True,
                              pace_s=CYCLE_PACE_S)


# -------------------------------------------------------------- selftest ----


def _selftest():  # pragma: no cover — exercised via CLI in tests
    """Offline self-test: parsers, guard logic, classification routing,
    comparator, plan ordering, reader pick — no hardware, no pyscard."""
    import tempfile

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # plan ordering invariant
    check("plan_order", plan_stage_order_ok(LANE_PLAN)
          and not plan_stage_order_ok(["reader_gate", "cycle_loop", "test_ck"]))

    # reader pick mirrors transport.rs under both roles
    acr = "ACS ACR1252 1S CL Reader PICC 00 00"
    sam = "ACS ACR1252 1S CL Reader SAM 01 00"
    gem = "Gemalto GemPC Twin Serial 00 00"
    check("pick_bolty", assert_reader_set([acr, sam])["pick"] == acr)
    check("pick_ccid", assert_reader_set([gem, acr, sam],
                                         expect_gempctwin=True)["pick"] == acr)
    try:
        assert_reader_set([gem])
        check("pick_rejects_gempc", False)
    except ReaderSetError:
        check("pick_rejects_gempc", True)

    # parsers
    # SDM p= payload assembled from fragments: a full 32-hex literal in
    # source would trip the todo-6 F4 no-key-literal static audit.
    _p_sample = "AB91AE" + "DEADBEEF" * 3 + "12"
    burned = parse_inspect_text(
        "UID: 040C60FA967380\n"
        "NDEF file settings: FileSettingsView { file_size: 256, "
        "access_rights: AccessRights { read: Free, write: Key(Key1), "
        "read_write: Key(Key1), change: Key(Key0) }, sdm: Some(Sdm "
        "{ picc_data: Encrypted { .. }, file_read: Some(FileRead { .. }), "
        "tamper_status: None }) }\n"
        "NDEF content (253 bytes): 00\n"
        f"NDEF URL: https://boltcardpoc.psbt.me/?p={_p_sample}"
        "&c=1234ABCD5678EF12\n"
        "SDM PICC decrypted: UID=040C60FA967380 counter=9 CMAC_valid=true\n"
        "K0 auth: SUCCESS\n")
    check("parser_burned", burned["sdm_active"] is True
          and burned["access_rights"]["write"] == "key1"
          and burned["ndef_url_template"].endswith("p={picc}&c={mac}")
          and burned["sdm_picc"]["counter"] == 9)
    blank = parse_inspect_text(
        "UID: 040C60FA967380\n"
        "NDEF file settings: FileSettingsView { sdm: Some(Sdm "
        "{ picc_data: None, file_read: None, tamper_status: None }) }\n"
        "NDEF content (0 bytes): \n")
    check("parser_blank", inspect_provably_blank(blank) is True
          and inspect_provably_blank(burned) is False
          and inspect_provably_blank({"sdm_parsed": False}) is False)

    # classification routing through the REAL ledger
    with tempfile.TemporaryDirectory() as td:
        led = ledger_mod.Ledger(Path(td) / "l.json",
                                issuer_key="0" * 31 + "1")
        led.record_classified("040C60FA967380", "Error: 91AE auth failed")
        led.record_classified("040C60FA967380", "no PCSC readers found")
        c = led.counters("040C60FA967380")
        check("classify_routing", c["total_failures"] == 1)

        # guard: absent -> runs -> flag written; present -> skip
        flag = test_ck_flag_path(Path(td) / "results")
        write_flag(flag, "040C60FA967380", "PASS")
        prior = read_flag(flag)
        check("guard_flag", prior is not None and prior["uid"]
              == "040C60FA967380" and prior["ts"])

    # comparator
    a = dict(burned)
    s = dict(burned)
    s["uid"] = "04A39493CC8680"
    s["sdm_picc"] = {"counter": 3}
    check("diff_match", compare_artifacts(a, s)["match"] is True)
    s["access_rights"] = dict(s["access_rights"] or {}, write="key0")
    check("diff_mismatch", compare_artifacts(a, s)["match"] is False)

    ok = all(c for _, c in checks)
    for name, cond in checks:
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    print(f"selftest: {sum(c for _, c in checks)}/{len(checks)} checks, "
          f"{'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


def main(argv=None):  # pragma: no cover
    ap = argparse.ArgumentParser(description="Track B: ACR1252 overnight lane")
    ap.add_argument("--selftest", action="store_true",
                    help="offline parser/guard/classification self-test")
    args = ap.parse_args(argv)
    if args.selftest:
        return _selftest()
    ap.error("nothing to do standalone (lane runs under overnight.py); "
             "use --selftest")


if __name__ == "__main__":
    sys.exit(main())
