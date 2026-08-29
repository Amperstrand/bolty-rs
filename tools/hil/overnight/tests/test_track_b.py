"""Track B (ACR1252 all-night lane) tests — plan todo 10.

All hardware is mocked: the bolty-cli subprocess runner, the pcscd
readers() list and the journal snapshot are injected fakes; the ledger is
the real todo-6 Ledger against a tmp path (classification routing is
load-bearing and must be proven against the real classifier).
"""

import json
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ledger as ledger_mod  # noqa: E402
import track_b  # noqa: E402

ACR_UID = "040C60FA967380"
ISSUER = "00000000000000000000000000000001"
URL = "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}"

ACR_PICC = "ACS ACR1252 1S CL Reader PICC 00 00"
ACR_SAM = "ACS ACR1252 1S CL Reader SAM 01 00"
GEMPC = "Gemalto GemPC Twin Serial 00 00"

READERS_BOLTY = [ACR_PICC, ACR_SAM]
READERS_CCID = [GEMPC, ACR_PICC, ACR_SAM]

# ---------------------------------------------------------------- fixtures ----

INSPECT_BLANK = f"""Connected to reader: {ACR_PICC}
UID: {ACR_UID}
Version: HW vendor=04 type=04 ver=30.00 | SW vendor=04 type=04 ver=01.02 | Batch=CF2E56 CW25 2021
NDEF file settings: FileSettingsView {{ file_type: StandardData, file_size: 256, comm_mode: Plain, access_rights: AccessRights {{ read: Free, write: Key(Key0), read_write: Key(Key0), change: Key(Key0) }}, sdm: Some(Sdm {{ picc_data: None, file_read: None, tamper_status: None }}) }}
NDEF content (0 bytes):
"""

INSPECT_BURNED = f"""Connected to reader: {ACR_PICC}
UID: {ACR_UID}
Version: HW vendor=04 type=04 ver=30.00 | SW vendor=04 type=04 ver=01.02 | Batch=CF2E56 CW25 2021
NDEF file settings: FileSettingsView {{ file_type: StandardData, file_size: 256, comm_mode: Plain, access_rights: AccessRights {{ read: Free, write: Key(Key1), read_write: Key(Key1), change: Key(Key0) }}, sdm: Some(Sdm {{ picc_data: Encrypted {{ key: Key1, offset: Offset(31), content: EncryptedContent {{ .. }} }}, file_read: Some(FileRead {{ .. }}), tamper_status: None }}) }}
NDEF content (253 bytes): 910108747970...0000

NDEF URL: https://boltcardpoc.psbt.me/?p=AB91AEBFDEADBEEF1234AB91AEBFDEAD&c=1234ABCD5678EF12

Derived keys (version 1):
  K0: 4057766867304a7610bbf7c31ed93ce1
  K1: 55da174c9608993dc27bb3f30a4a7316
  K2: 66e89f0211ccb633f38aadda77bf0e34

SDM PICC decrypted: UID={ACR_UID} counter=42 CMAC_valid=true
K0 auth: SUCCESS
"""

INSPECT_UNPARSEABLE = f"""Connected to reader: {ACR_PICC}
UID: {ACR_UID}
NDEF content (0 bytes):
"""  # file-settings line missing -> NOT provably blank (fail-safe skip)

TESTCK_PASS = f"""Card UID: {ACR_UID}

[testck] ChangeKey A/B test — round-trip on key 1
[testck] Auth K0 (zeros): OK
[testck] Key 1 version before: 0x00
[testck] Step 1: ChangeKey(1, zero→test, ver=0x01)
[testck]   Result: OK
[testck]   Step 1: PASS
[testck] Step 2: ChangeKey(1, test→zero, ver=0x00)
[testck]   Step 2: PASS

✅ testck: ALL PASS — ChangeKey verified
"""

UID_OUT = f"Connected to reader: {ACR_PICC}\nUID: {ACR_UID}\n"
UID_WRONG = "Connected to reader: ACS ACR1252 1S CL Reader PICC 00 00\nUID: 043365FA967380\n"
PICC_OK = f"""Card UID:  {ACR_UID}
NDEF URL: https://boltcardpoc.psbt.me/?p=AB91AEBFDEADBEEF1234AB91AEBFDEAD&c=1234ABCD5678EF12

Extracted SDM parameters:
  p = AB91AEBFDEADBEEF1234AB91AEBFDEAD
  c = 1234ABCD5678EF12

PICC data (decrypted with K1):
  UID:            {ACR_UID}
  Read counter:   42
  UID matches:    YES
  CMAC valid:     YES

SDM verification PASSED.
"""

BREAKER_OUT = "🛑 CIRCUIT BREAKER: 10 total auth failures. Aborting to protect the card.\n"
TRANSPORT_OUT = "Error: no PCSC readers found\nHint: connect a PCSC smart card reader.\n"
AUTHFAIL_OUT = "Error: authentication failed (91AE AuthFailed)\n"
CYCLE_PASS_OUT = (
    "═══ CYCLE: BURN ═══\nburn complete\n"
    "═══ CYCLE: WIPE ═══\nwipe complete\n"
    "═══ CYCLE: RE-BURN ═══\nburn complete\n"
    "🎉 Full cycle completed successfully!\n"
)
DIAGNOSE_PROVISIONED = f"=== DIAGNOSE ===\nUID:            {ACR_UID}\nCard state:     PROVISIONED\n"


# ---------------------------------------------------------------- helpers ----

class FakeClock:
    def __init__(self, t0=0.0):
        self.mono = t0
        self.wall = 1_800_000_000.0

    def monotonic(self):
        return self.mono

    def time(self):
        return self.wall

    def sleep(self, s):
        self.mono += max(0.0, s)


class FakeRunner:
    """Scripted bolty-cli: pops one (rc, text) per call, records argv."""

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        if self.responses:
            rc, text = self.responses.pop(0)
            return rc, text
        return 0, ""

    def sub(self, name):
        return [c for c in self.calls if name in c]


class FuncRunner:
    """Function-backed runner for scripted long runs."""

    def __init__(self, fn):
        self.fn, self.calls = fn, []

    def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        return self.fn(argv, timeout)

    def sub(self, name):
        return [c for c in self.calls if name in c]


class FakeCtx:
    def __init__(self, clock, led):
        self.name = "track_b_acr"
        self.cards = ("acr",)
        self.pace_s = 60.0
        self.dry_run = False
        self.clock = clock
        self.ledger = led
        self.store = None
        self.rows = []
        self._run = True
        self._phase = "WINDOW1"

    def running(self):
        return self._run

    def paused(self):
        return False

    @property
    def phase(self):
        return self._phase

    def sleep(self, s):
        self.clock.sleep(s)

    def card(self, card_id):
        return nullcontext()

    def row(self, **f):
        r = dict(f)
        self.rows.append(r)
        return r

    def skip(self, reason, **f):
        return self.row(type="SKIP", status="SKIP", reason=reason, **f)

    def anomaly(self, kind, **f):
        return self.row(type="anomaly", status="ANOMALY", kind=kind, **f)

    def event(self, kind, **f):
        return self.row(type="event", kind=kind, **f)

    def of(self, rtype):
        return [r for r in self.rows if r.get("type") == rtype]


def make_track(tmp_path, clock=None, runner=None, readers=None, led=None, **kw):
    clock = clock or FakeClock()
    readers = readers if readers is not None else READERS_BOLTY
    led = led or ledger_mod.Ledger(tmp_path / "ledger.json", issuer_key=ISSUER)
    ctx = FakeCtx(clock, led)

    def readers_fn():
        if isinstance(readers, Exception):
            raise readers
        return list(readers)

    tb = track_b.TrackB(
        runner=runner or FakeRunner(),
        readers_fn=readers_fn,
        journal_fn=lambda: "fake journal snapshot",
        ledger=led,
        results_root=tmp_path / "results",
        clock=clock,
        uid=ACR_UID,
        issuer_key=ISSUER,
        url=URL,
        **kw,
    )
    return tb, ctx, led


# ------------------------------------------------------------ plan ordering ----

def test_plan_orders_test_ck_strictly_before_first_cycle():
    assert "test_ck" in track_b.LANE_PLAN and "cycle_loop" in track_b.LANE_PLAN
    assert track_b.plan_stage_order_ok(track_b.LANE_PLAN)
    assert not track_b.plan_stage_order_ok(
        ["reader_gate", "cycle_loop", "test_ck"])  # after a burn -> forbidden
    assert not track_b.plan_stage_order_ok(["reader_gate", "cycle_loop"])  # missing
    assert not track_b.plan_stage_order_ok(
        ["test_ck", "test_ck", "cycle_loop"])  # duplicated


# ------------------------------------------------------------ test-ck guard ----

def test_guard_flag_absent_runs_once_then_writes_flag(tmp_path):
    runner = FakeRunner([
        (0, INSPECT_BLANK),   # auth-free blankness proof
        (0, UID_OUT),         # uid assertion immediately before the call
        (0, TESTCK_PASS),     # test-ck itself
    ])
    tb, ctx, led = make_track(tmp_path, runner=runner)
    tb.stage_test_ck(ctx)

    flag = track_b.test_ck_flag_path(tmp_path / "results")
    assert flag.exists(), "guard flag must be written after the attempt"
    content = track_b.read_flag(flag)
    assert content is not None, "flag content must parse"
    assert content["uid"] == ACR_UID
    assert content["outcome"] == "PASS"
    assert content["ts"]  # timestamp present
    assert len(runner.sub("test-ck")) == 1
    assert led.counters(ACR_UID)["ops_by_type"].get("test_ck") == 1
    assert any(r.get("type") == "test_ck" and r.get("status") == "PASS"
               for r in ctx.rows)


def test_guard_flag_present_skips(tmp_path):
    flagdir = tmp_path / "results"
    flagdir.mkdir(parents=True)
    track_b.write_flag(track_b.test_ck_flag_path(flagdir), ACR_UID, "PASS")
    runner = FakeRunner()
    tb, ctx, _ = make_track(tmp_path, runner=runner)
    tb.stage_test_ck(ctx)

    assert runner.calls == [], "flag present => zero card contact"
    skips = ctx.of("SKIP")
    assert skips and "test-ck" in skips[-1]["reason"]


def test_guard_never_runs_after_a_burn(tmp_path):
    runner = FakeRunner()
    tb, ctx, _ = make_track(tmp_path, runner=runner)
    tb.burns_started = 1  # a cycle was already issued this process
    tb.stage_test_ck(ctx)

    assert runner.sub("test-ck") == []
    assert not track_b.test_ck_flag_path(tmp_path / "results").exists()
    assert ctx.of("SKIP"), "must be an honest SKIP row"


@pytest.mark.parametrize("inspect_text", [INSPECT_BURNED, INSPECT_UNPARSEABLE])
def test_guard_requires_provably_blank_card(tmp_path, inspect_text):
    runner = FakeRunner([(0, inspect_text)])
    tb, ctx, _ = make_track(tmp_path, runner=runner)
    tb.stage_test_ck(ctx)

    assert runner.sub("test-ck") == [], \
        "non-blank/unprovable card => never authenticate with factory-zero K0"
    assert ctx.of("SKIP")


def test_flag_path_is_fixed_outside_dated_dirs():
    p = track_b.test_ck_flag_path()
    assert p == Path(track_b.__file__).resolve().parent / "results" / "TEST_CK_DONE"
    assert p.parent.name == "results"


# ------------------------------------------------------ classification routing ----

def test_cycle_91ae_counts_in_ledger_and_fails_row(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (1, AUTHFAIL_OUT)])
    tb, ctx, led = make_track(tmp_path, runner=runner)
    tb._cycle_tick(ctx)

    assert led.counters(ACR_UID)["total_failures"] == 1
    assert led.counters(ACR_UID)["consecutive_failures"] == 1
    assert any(r.get("status") == "FAIL" for r in ctx.of("cycle"))
    assert runner.sub("cycle"), "the cycle itself must have been issued"


def test_transport_failure_is_isolated_from_ledger(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (2, TRANSPORT_OUT)])
    tb, ctx, led = make_track(tmp_path, runner=runner)
    tb._cycle_tick(ctx)

    c = led.counters(ACR_UID)
    assert c["total_failures"] == 0 and c["auth_attempts"] == 0
    journal = led.journal_path.read_text()
    assert '"event": "transport"' in journal
    assert any("transport" in str(r.get("kind", "")) for r in ctx.rows)


def test_uid_mismatch_blocks_mutation(tmp_path):
    runner = FakeRunner([(0, UID_WRONG)])  # the exclusion-listed stuck card
    tb, ctx, led = make_track(tmp_path, runner=runner)
    tb._cycle_tick(ctx)

    assert runner.sub("cycle") == [], "mutation must never run on a uid mismatch"
    assert led.counters(ACR_UID)["ops_by_type"] == {}
    assert any("uid" in str(r.get("kind", r.get("reason", ""))) for r in ctx.rows)


# ---------------------------------------------------- breaker + aware-pause ----

def test_breaker_exit_during_pause_lane_survives(tmp_path):
    clock = FakeClock()
    runner = FakeRunner([
        (0, UID_OUT), (6, BREAKER_OUT),     # breaker trip, reader gone mid-burn
        (0, UID_OUT), (0, CYCLE_PASS_OUT),  # rescan over: lane RESUMES + passes
    ])
    tb, ctx, led = make_track(tmp_path, clock=clock, runner=runner)
    probes = {"n": 0}

    def readers_fn():
        probes["n"] += 1
        if probes["n"] <= 2:  # two failed wait probes (pause short-circuits
            # the disrupted check, so both probes belong to _wait_disrupted)
            raise RuntimeError("pcscd down (role-switch rescan)")
        return list(READERS_BOLTY)
    tb.readers_fn = readers_fn
    tb.pause("role-switch rescan")

    tb._cycle_tick(ctx)  # breaker exit inside the window -> backoff, not FAIL
    tb._cycle_tick(ctx)  # readers back -> resume -> cycle passes

    assert tb.cycles_passed == 1, "lane must survive the breaker and resume"
    assert not tb.is_paused(), "resume on reader return"
    backoffs = [r["sleep_s"] for r in ctx.of("backoff")]
    assert backoffs == [5, 10], "backoff 5->120 sequence while disrupted"
    assert not any(r.get("lane_fail") for r in ctx.of("cycle")), \
        "breaker inside a disruption window must never kill the lane"
    assert any(r.get("status") == "PASS" for r in ctx.of("cycle"))
    # breaker banner text classifies auth_fail -> honestly counted (1 per block)
    assert led.counters(ACR_UID)["total_failures"] == 1


def test_genuine_repeated_failures_fail_the_lane(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (2, TRANSPORT_OUT)] * 3)
    tb, ctx, _ = make_track(tmp_path, runner=runner)

    alive = True
    for _ in range(10):
        alive = tb._cycle_tick(ctx)
        if not alive:
            break

    assert not alive, "lane must stop after repeated non-window failures"
    assert len(runner.sub("cycle")) == 3
    assert any(r.get("status") == "FAIL" and r.get("type") == "cycle"
               for r in ctx.rows)


def test_aware_pause_backoff_escalates_5_to_120(tmp_path):
    clock = FakeClock()
    tb, ctx, _ = make_track(tmp_path, clock=clock)
    probes = {"n": 0}

    def readers_fn():
        probes["n"] += 1
        if probes["n"] <= 7:  # 7 unhealthy probes -> 7 backoff steps
            raise RuntimeError("pcscd down")
        return list(READERS_BOLTY)
    tb.readers_fn = readers_fn
    tb.pause("role-switch rescan")
    tb._wait_disrupted(ctx, "test")

    steps = [r["sleep_s"] for r in ctx.of("backoff")]
    assert steps == [5, 10, 20, 40, 80, 120, 120]
    assert not tb.is_paused(), "reader return auto-resumes the lane"


# ------------------------------------------------------------- reader set ----

def test_reader_set_bolty_window_pick_is_acr_picc():
    info = track_b.assert_reader_set(READERS_BOLTY)
    assert info["pick"] == ACR_PICC
    assert info["acr_picc"] == [ACR_PICC]


def test_reader_set_ccid_window_still_picks_acr_never_gempc():
    info = track_b.assert_reader_set(READERS_CCID, expect_gempctwin=True)
    assert info["pick"] == ACR_PICC, "bolty-cli PICC pick must never be GemPCTwin"


def test_reader_set_missing_acr_or_gempc_rejected():
    with pytest.raises(track_b.ReaderSetError):
        track_b.assert_reader_set([ACR_SAM, GEMPC])  # ACR PICC slot gone
    with pytest.raises(track_b.ReaderSetError):
        track_b.assert_reader_set([GEMPC], expect_gempctwin=True)  # pick would be GemPC
    with pytest.raises(track_b.ReaderSetError):
        track_b.assert_reader_set(READERS_BOLTY, expect_gempctwin=True)  # ccid w/o GemPC


def test_bolty_cli_pick_mirrors_transport_rs():
    assert track_b.bolty_cli_pick(READERS_CCID) == ACR_PICC
    assert track_b.bolty_cli_pick([ACR_SAM, "Foo Reader"]) == "Foo Reader"
    assert track_b.bolty_cli_pick([]) is None


# --------------------------------------------------------------- monitors ----

def test_monitor_runs_uid_picc_diagnose_when_state_known(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (0, PICC_OK), (0, DIAGNOSE_PROVISIONED)])
    tb, ctx, _ = make_track(tmp_path, runner=runner)
    tb.expected_state = "provisioned"
    tb._monitor_tick(ctx)

    assert len(runner.sub("uid")) == 1
    assert len(runner.sub("picc")) == 1
    assert len(runner.sub("diagnose")) == 1
    kinds = [r.get("class") for r in ctx.of("monitor")]
    assert len(kinds) == 3, "every monitor output carries its classification (proof)"


def test_monitor_skips_diagnose_when_state_unknown(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (0, PICC_OK)])
    tb, ctx, _ = make_track(tmp_path, runner=runner)
    tb.expected_state = "unknown"  # e.g. after a failed cycle
    tb._monitor_tick(ctx)

    assert runner.sub("diagnose") == [], \
        "diagnose static-test-key probe risk on unknown cards => skipped"
    assert any("diagnose" in r.get("reason", "") for r in ctx.of("SKIP"))


def test_monitor_91ae_is_recorded_not_hidden(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (0, PICC_OK),
                         (1, "Card state: (auth failed 91AE)\n")])
    tb, ctx, led = make_track(tmp_path, runner=runner)
    tb.expected_state = "provisioned"
    tb._monitor_tick(ctx)

    assert led.counters(ACR_UID)["total_failures"] == 1
    assert tb.expected_state == "unknown"


def test_pcscd_health_error_snapshots_journal(tmp_path):
    tb, ctx, _ = make_track(tmp_path)

    def dead():
        raise RuntimeError("pcscd dead")
    tb.readers_fn = dead
    tb._health_tick(ctx)

    snaps = list((tmp_path / "results").rglob("pcscd_journal_*.txt"))
    assert snaps and "fake journal snapshot" in snaps[0].read_text()
    assert any("pcscd" in str(r.get("kind", "")) for r in ctx.rows)


# ------------------------------------------------------------ differential ----

def test_inspect_parser_extracts_canonical_fields():
    art = track_b.parse_inspect_text(INSPECT_BURNED)
    assert art["uid"] == ACR_UID
    assert art["access_rights"] == {"read": "free", "write": "key1",
                                    "read_write": "key1", "change": "key0"}
    assert art["sdm_active"] is True
    assert art["ndef_url_template"] == \
        "https://boltcardpoc.psbt.me/?p={picc}&c={mac}"
    assert art["k0_auth"] == "SUCCESS"
    assert art["sdm_picc"]["counter"] == 42
    assert art["sdm_picc"]["cmac_valid"] is True


def test_differential_match_modulo_uid_and_ctr():
    acr = track_b.parse_inspect_text(INSPECT_BURNED)
    stick = json.loads(json.dumps(acr))
    stick["uid"] = "04A39493CC8680"
    stick["sdm_picc"]["counter"] = 7
    result = track_b.compare_artifacts(acr, stick)
    assert result["match"] is True
    assert result["markdown"].startswith("###")

    stick["access_rights"]["write"] = "key0"
    stick["sdm_active"] = False
    result = track_b.compare_artifacts(acr, stick)
    assert result["match"] is False
    differing = [f["field"] for f in result["fields"] if f["verdict"] == "MISMATCH"]
    assert set(differing) == {"access_rights", "sdm_active"}


def test_differential_missing_side_field_is_unverifiable_not_mismatch():
    acr = track_b.parse_inspect_text(INSPECT_BURNED)
    stick = {"uid": "04A39493CC8680"}  # stick artifact lacking fields
    result = track_b.compare_artifacts(acr, stick)
    assert result["match"] is True  # nothing contradicts
    assert any(f["verdict"] == "MISSING" for f in result["fields"])


def test_differential_capture_after_burn_stores_artifact(tmp_path):
    runner = FakeRunner([(0, UID_OUT), (0, CYCLE_PASS_OUT), (0, INSPECT_BURNED)])
    tb, ctx, _ = make_track(tmp_path, runner=runner)
    tb._cycle_tick(ctx)

    arts = list((tmp_path / "results").rglob("acr_inspect_*.json"))
    assert arts, "inspect artifact must be stored after each burn"
    art = json.loads(arts[0].read_text())
    assert art["uid"] == ACR_UID


# ------------------------------------------------------- pacing and budget ----

def _pacing_track(tmp_path, budget_s):
    clock = FakeClock()

    def resp(argv, timeout=None):
        if "cycle" in argv:
            return 0, CYCLE_PASS_OUT
        if "inspect" in argv and "--issuer-key" in argv:
            return 0, INSPECT_BURNED
        if "test-ck" in argv:
            return 0, TESTCK_PASS
        return 0, UID_OUT

    tb, ctx, _ = make_track(tmp_path, clock=clock, runner=FuncRunner(resp),
                            budget_s=budget_s)
    return tb, ctx, clock


def test_cycle_pacing_at_least_60s_with_fake_clock(tmp_path):
    tb, ctx, clock = _pacing_track(tmp_path, budget_s=250)
    tb.cycle_loop(ctx)
    starts = [r["mono"] for r in ctx.of("cycle") if r.get("status") == "PASS"]
    assert len(starts) == 3
    assert min(b - a for a, b in zip(starts, starts[1:])) >= 60.0
    assert clock.monotonic() <= 251.0, "hard wall-clock end honored"


def test_budget_prevents_starting_unfinishable_cycle(tmp_path):
    tb, ctx, clock = _pacing_track(tmp_path, budget_s=130)
    tb.cycle_loop(ctx)
    # t=0 cycle ok; t=60: 60+120=180 > 130 -> must NOT start a second cycle
    starts = [r for r in ctx.of("cycle") if r.get("status") == "PASS"]
    assert len(starts) == 1
    assert ctx.of("budget_skip"), "an honest row records the refused cycle"
    assert ctx.of("budget_end")


def test_monitor_cadence_five_minutes(tmp_path):
    tb, ctx, clock = _pacing_track(tmp_path, budget_s=310)
    tb.cycle_loop(ctx)
    mon = [r for r in ctx.of("monitor") if r.get("op") == "picc"]
    assert len(mon) == 1, "monitor fires every 300s, once in a 310s budget"
    health = ctx.of("health")
    assert len(health) >= 5, "pcscd health poll every 60s"


# ------------------------------------------------------------ integration ----

class MutationWindowClosed(Exception):
    pass


class DrainedCtx(FakeCtx):
    def card(self, card_id):
        raise MutationWindowClosed(f"mutation window closed for {card_id!r}")


def test_drain_window_close_is_honest_skip_not_crash(tmp_path):
    clock = FakeClock()
    led = ledger_mod.Ledger(tmp_path / "l.json", issuer_key=ISSUER)
    ctx = DrainedCtx(clock, led)
    tb, _, _2 = make_track(tmp_path, clock=clock, runner=FakeRunner())
    tb._cycle_tick(ctx)
    assert any("mutation window closed" in r.get("reason", "")
               for r in ctx.of("SKIP"))
    assert tb.burns_started == 0, "no burn counted when the window was closed"


def test_register_records_skip_when_unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv("HIL_ISSUER", raising=False)
    monkeypatch.delenv("HIL_UID_ACR", raising=False)
    clock = FakeClock()
    ctx = FakeCtx(clock, ledger_mod.Ledger(tmp_path / "l.json"))
    track_b.register(ctx)
    assert any("unconfigured" in r.get("reason", "") for r in ctx.of("SKIP"))


def test_build_lane_shape():
    spec = track_b.build_lane()
    assert spec.name == "track_b_acr"
    assert spec.window == "all_night"
    assert spec.cards == ("acr",)
    assert spec.needs_pcscd is True
    assert callable(spec.target)


def test_selftest_cli_offline():
    proc = subprocess.run(
        [sys.executable, str(Path(track_b.__file__).resolve()), "--selftest"],
        capture_output=True, text=True, timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ------------------------------------------------ stale pcsc context ----

def _stub_smartcard(monkeypatch, readers_fn, ctx):
    import types

    sys_mod = types.ModuleType("smartcard.System")
    sys_mod.readers = staticmethod(readers_fn)
    ctx_mod = types.ModuleType("smartcard.pcsc.PCSCContext")
    ctx_mod.PCSCContext = ctx
    pcsc_mod = types.ModuleType("smartcard.pcsc")
    pcsc_mod.PCSCContext = ctx
    monkeypatch.setitem(sys.modules, "smartcard.System", sys_mod)
    monkeypatch.setitem(sys.modules, "smartcard.pcsc", pcsc_mod)
    monkeypatch.setitem(sys.modules, "smartcard.pcsc.PCSCContext", ctx_mod)


def test_default_readers_fn_renews_stale_pcsc_context(monkeypatch):
    # pcscd restarted under the long-lived orchestrator -> singleton context
    # stale -> default_readers_fn must renew once and recover (1d227b5)
    calls = {"n": 0, "renewed": 0}

    class Ctx:
        @staticmethod
        def renewContext():
            calls["renewed"] += 1

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("ListReadersException: stale context")
        return ["ACS ACR1252 Dual Reader 00 00"]

    _stub_smartcard(monkeypatch, flaky, Ctx)
    assert track_b.default_readers_fn() == ["ACS ACR1252 Dual Reader 00 00"]
    assert calls["renewed"] == 1


def test_default_readers_fn_gives_up_after_one_renew(monkeypatch):
    calls = {"renewed": 0}

    class Ctx:
        @staticmethod
        def renewContext():
            calls["renewed"] += 1

    def always_dead():
        raise RuntimeError("EstablishContextException: pcscd down")

    _stub_smartcard(monkeypatch, always_dead, Ctx)
    with pytest.raises(RuntimeError, match="EstablishContextException"):
        track_b.default_readers_fn()
    assert calls["renewed"] == 1
