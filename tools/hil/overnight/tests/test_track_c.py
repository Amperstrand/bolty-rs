"""Track C (CI-parity host-audit runner) tests — plan todo 11.

No cargo, no network, no real clone: every executed command goes through
an injected fake exec_fn (the same seam TrackC uses for _subprocess_exec),
except the timeout test which drives the REAL subprocess path against a
short `sleep` so the kill/process-group machinery is genuinely exercised.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import track_c  # noqa: E402

BOLTY = track_c.BOLTY_REPO
CCID = track_c.CCID_REPO

PLAIN_COMMANDS = tuple(c for c in track_c.COMMANDS if c.kind == "plain")
SPEC_CMD = next(c for c in track_c.COMMANDS if c.kind == "spec_quote")

# (repo, name, argv, cwd, env-overlay, quick) — the EXACT expected table.
EXPECTED_TABLE = [
    ("bolty-rs", "bolty/fmt",
     ("cargo", "fmt", "--check"), BOLTY, {}, True),
    ("bolty-rs", "bolty/clippy",
     ("cargo", "clippy", "--workspace", "--exclude", "bolty-esp32",
      "--", "-D", "warnings"), BOLTY, {}, False),
    ("bolty-rs", "bolty/test-workspace",
     ("cargo", "test", "--workspace", "--exclude", "bolty-esp32"),
     BOLTY, {}, False),
    ("bolty-rs", "bolty/test-security",
     ("cargo", "test", "--workspace", "--exclude", "bolty-esp32",
      "security"), BOLTY, {}, False),
    ("bolty-rs", "bolty/spec-quote", (), BOLTY, {}, False),
    ("ccid-firmware-rs", "ccid/fmt",
     ("cargo", "fmt", "--check"), CCID, {}, True),
    ("ccid-firmware-rs", "ccid/clippy-f469",
     ("cargo", "clippy", "--release", "--target", "thumbv7em-none-eabihf",
      "--", "-D", "warnings"), CCID, {"RUSTFLAGS": "-D warnings"}, False),
    ("ccid-firmware-rs", "ccid/clippy-f746",
     ("cargo", "clippy", "--release", "--target", "thumbv7em-none-eabihf",
      "--no-default-features",
      "--features", "stm32f746,profile-cherry-smartterminal-st2xxx",
      "--", "-D", "warnings"), CCID, {"RUSTFLAGS": "-D warnings"}, False),
    ("ccid-firmware-rs", "ccid/test-workspace",
     ("cargo", "test", "--workspace", "--target", "x86_64-unknown-linux-gnu"),
     CCID, {}, False),
    ("ccid-firmware-rs", "ccid/test-esp32",
     ("cargo", "test", "--target", "x86_64-unknown-linux-gnu"),
     CCID / "firmware" / "esp32-ccid", {}, False),
    ("ccid-firmware-rs", "ccid/test-iso14443",
     ("cargo", "test", "--features", "std",
      "--target", "x86_64-unknown-linux-gnu"),
     CCID / "vendor" / "iso14443-rs", {}, False),
    ("ccid-firmware-rs", "ccid/verify-reproducibility",
     ("scripts/verify-reproducibility.sh",), CCID, {}, False),
]


# ---------------------------------------------------------------- helpers ----


class FakeClock:
    """monotonic() advances `step` per call — deterministic duration_s."""

    def __init__(self, step=7.0):
        self.t = 1000.0
        self.step = step

    def monotonic(self):
        self.t += self.step
        return self.t


class Recorder:
    """Fake exec_fn: logs every call, answers from a handler(argv)->tuple."""

    def __init__(self, handler):
        self.calls = []
        self.handler = handler

    def __call__(self, argv, cwd, env, timeout_s):
        argv = tuple(argv)
        self.calls.append(
            {"argv": argv, "cwd": Path(cwd), "env": env, "timeout": timeout_s})
        rc, out = self.handler(argv)
        return rc, out, False


def ok_all(_argv):
    return 0, "ok\n"


def read_rows(tmp_path):
    lines = (tmp_path / "track_c.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


# ------------------------------------------------------------------ tests ----


def test_command_table_exact():
    """Dry enumeration == the expected 12-command CI list (todo-11 fixture)."""
    assert len(track_c.COMMANDS) == 12
    assert [c.name for c in track_c.COMMANDS] == [e[1] for e in EXPECTED_TABLE]
    for cmd, (repo, name, argv, cwd, env, quick) in zip(
            track_c.COMMANDS, EXPECTED_TABLE):
        assert (cmd.repo, cmd.name, cmd.argv, cmd.cwd,
                dict(cmd.env or {}), cmd.quick) == (repo, name, argv, cwd,
                                                    env, quick)
    assert SPEC_CMD.kind == "spec_quote"
    assert "greatspectations" in SPEC_CMD.display
    assert "git ls-files" in SPEC_CMD.display


def test_quick_subset_is_fmt_only(tmp_path):
    """--quick selects exactly the two cargo fmt --check commands."""
    sel = track_c.select_commands(track_c.COMMANDS, quick=True)
    assert [c.name for c in sel] == ["bolty/fmt", "ccid/fmt"]
    assert all(c.argv == ("cargo", "fmt", "--check") for c in sel)

    rec = Recorder(ok_all)
    tc = track_c.TrackC(exec_fn=rec, results_dir=tmp_path, clock=FakeClock())
    rows, summary = tc.run_audit(quick=True)
    assert [r["name"] for r in rows] == ["bolty/fmt", "ccid/fmt"]
    assert summary["fail_total"] == 0
    assert len(rec.calls) == 2


def test_fail_isolation_and_summary(tmp_path):
    """One FAIL row is recorded; every later command still runs."""
    def handler(argv):
        if "--no-default-features" in argv:
            return 1, "error: lint `dead_code` in smartcard_bitbang.rs\n"
        return 0, "ok\n"

    rec = Recorder(handler)
    tc = track_c.TrackC(commands=PLAIN_COMMANDS, exec_fn=rec,
                        results_dir=tmp_path, clock=FakeClock())
    rows, summary = tc.run_audit()

    assert len(rows) == 11
    fails = [r for r in rows if r["status"] == "FAIL"]
    assert len(fails) == 1 and fails[0]["name"] == "ccid/clippy-f746"
    assert fails[0]["rc"] == 1
    assert "dead_code" in fails[0]["tail"]
    # commands after the failure (incl. the last one) still executed
    assert rec.calls[-1]["argv"] == ("scripts/verify-reproducibility.sh",)
    assert len(rec.calls) == 11
    assert summary["repos"]["bolty-rs"] == {"pass": 4, "fail": 0, "skip": 0}
    assert summary["repos"]["ccid-firmware-rs"] == {"pass": 6, "fail": 1,
                                                    "skip": 0}
    assert summary["fail_total"] == 1


def test_timeout_enforced_via_subprocess_and_isolated(tmp_path):
    """Real subprocess timeout: hung child killed at the deadline, rc=-9,
    timed_out row recorded as FAIL, following commands unaffected."""
    hang = track_c.AuditCommand("bolty-rs", "bolty/hang", BOLTY, ("sleep", "30"))
    ok = track_c.AuditCommand("bolty-rs", "bolty/true", BOLTY, ("true",))
    tc = track_c.TrackC(commands=(hang, ok), timeout_s=0.5,
                        results_dir=tmp_path)
    rows, summary = tc.run_audit()

    assert rows[0]["timed_out"] is True
    assert rows[0]["rc"] == -9
    assert rows[0]["status"] == "FAIL"
    assert rows[0]["duration_s"] < 10  # killed at ~0.5s, not 30s
    assert "timed out after 0.5s" in rows[0]["tail"]
    assert rows[1]["status"] == "PASS" and rows[1]["rc"] == 0
    assert summary["fail_total"] == 1


def test_incremental_persistence_and_timeout_passthrough(tmp_path):
    """Each row is appended the moment its command finishes (the next
    command already sees it on disk), the default timeout reaches the
    executor, and fake-clock durations are deterministic."""
    seen_before = []

    def handler(argv):
        rows_now = read_rows(tmp_path) if (tmp_path / "track_c.jsonl").exists() else []
        seen_before.append((tuple(argv), len([r for r in rows_now
                                              if r.get("type") != "summary"])))
        return 0, "ok\n"

    rec = Recorder(handler)
    tc = track_c.TrackC(commands=PLAIN_COMMANDS, exec_fn=rec,
                        results_dir=tmp_path, clock=FakeClock(step=7.0))
    rows, summary = tc.run_audit()

    # before exec #k (0-based), exactly k result rows were already persisted
    assert seen_before == [(c["argv"], i) for i, c in enumerate(rec.calls)]
    # default per-command timeout flowed into every exec call
    assert {c["timeout"] for c in rec.calls} == {track_c.DEFAULT_TIMEOUT_S}
    assert track_c.DEFAULT_TIMEOUT_S == 1800
    # fake clock: two monotonic() calls per exec -> duration 7.0s per row
    assert all(r["duration_s"] == 7.0 for r in rows)
    # JSONL: 11 result rows + 1 summary row, in command order
    persisted = read_rows(tmp_path)
    assert [r["name"] for r in persisted if r.get("type") != "summary"] \
        == [c.name for c in PLAIN_COMMANDS]
    assert persisted[-1]["type"] == "summary"
    assert persisted[-1]["fail_total"] == 0
    assert summary["skip_total"] == 0


def test_spec_quote_offline_skip(tmp_path):
    """Network failure on the spec clone -> SKIP{reason:offline}, the
    greatspectations step is never attempted, the audit continues."""
    def handler(argv):
        if argv[:3] == ("git", "clone", "--depth=1"):
            return (128, "fatal: unable to access "
                    "'https://github.com/boltcard/boltcard.git': "
                    "Could not resolve host: github.com\n")
        return 0, "ok\n"

    rec = Recorder(handler)
    tc = track_c.TrackC(exec_fn=rec, results_dir=tmp_path, clock=FakeClock())
    rows, summary = tc.run_audit()

    spec_rows = [r for r in rows if r["name"] == "bolty/spec-quote"]
    assert len(spec_rows) == 1
    spec = spec_rows[0]
    assert spec["status"] == "SKIP" and spec["reason"] == "offline"
    assert spec["rc"] == 128 and spec["timed_out"] is False
    assert "Could not resolve host" in spec["tail"]
    assert spec["cmd"].startswith("git clone --depth=1")
    # no greatspectations / ls-files call happened
    assert not any("greatspectations" in c["argv"] for c in rec.calls)
    assert not any(c["argv"][:2] == ("git", "ls-files") for c in rec.calls)
    # every other command ran; the offline SKIP is not a FAIL
    assert len(rows) == 12
    assert summary["repos"]["bolty-rs"] == {"pass": 4, "fail": 0, "skip": 1}
    assert summary["fail_total"] == 0 and summary["skip_total"] == 1


def test_spec_quote_online_invocation(tmp_path):
    """Online path: clone -> ls-files -> greatspectations with the EXACT
    AGENTS.md flags; specquotes.toml copied UNCHANGED into the temp dir
    (greatspectations resolves relative source paths against the config
    dir, so the copy points at the temp clone)."""
    gs_calls = []

    def handler(argv):
        if argv[:3] == ("git", "clone", "--depth=1"):
            assert argv[3] == track_c.SPEC_URL
            assert Path(argv[4]).name == "spec"
            return 0, "cloned\n"
        if argv[:2] == ("git", "ls-files"):
            assert argv[2:] == track_c.GS_LS_FILES_PATHSPECS
            return 0, ("crates/bolty-core/src/lib.rs\n"
                       "crates/bolty-ntag/src/lib.rs\n")
        if "greatspectations" in argv:
            gs_calls.append(argv)
            cfg = Path(argv[argv.index("--config") + 1])
            assert cfg.name == "specquotes.toml"
            assert cfg.parent.name.startswith("trackc-spec-")
            assert cfg.read_text() == (BOLTY / "specquotes.toml").read_text()
            return 0, "22 spec quotes verified, 0 drift\n"
        return 0, "ok\n"

    rec = Recorder(handler)
    tc = track_c.TrackC(exec_fn=rec, results_dir=tmp_path, clock=FakeClock())
    rows, summary = tc.run_audit()

    assert len(gs_calls) == 1
    gs = gs_calls[0]
    assert gs[gs.index("-k") + 1:] == ("crates/bolty-core/src/lib.rs",
                                       "crates/bolty-ntag/src/lib.rs")
    assert gs[gs.index("--comment-start") + 1] == "// "
    assert gs[gs.index("--comment-continue") + 1] == "//"
    spec = next(r for r in rows if r["name"] == "bolty/spec-quote")
    assert spec["status"] == "PASS" and spec["rc"] == 0
    assert "22 spec quotes verified" in spec["tail"]
    assert summary["fail_total"] == 0 and summary["skip_total"] == 0


def test_list_prints_enumeration_without_executing(capsys, monkeypatch):
    """--list enumerates all 12 commands (names, cwds, exact cmd strings)
    and executes nothing."""

    def boom(*_a, **_k):  # pragma: no cover — must never run
        raise AssertionError("--list must not execute commands")

    monkeypatch.setattr(track_c, "_subprocess_exec", boom)
    assert track_c.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "command list (12)" in out
    for _repo, name, argv, _cwd, _env, _quick in EXPECTED_TABLE:
        assert name in out
        if argv:
            assert track_c._display(argv) in out
    assert "greatspectations check --config specquotes.toml" in out
    assert out.count("(quick)") == 2
    assert "thumbv7em-none-eabihf" in out
    assert "x86_64-unknown-linux-gnu" in out


def test_register_lane_protocol_and_build_lane(tmp_path, monkeypatch):
    """register(ctx): dry-run enumerates only; wet run mirrors every JSONL
    row into ctx.row (type ci/summary) and honors a stopped lane with SKIP
    rows for the remainder. build_lane() duck-types the todo-5 LaneSpec."""

    class FakeCtx:
        def __init__(self, dry=False, alive=True):
            self.store = type("S", (), {"dir": tmp_path})()
            self.dry_run = dry
            self._alive = alive
            self.rows = []

        def row(self, **fields):
            self.rows.append(fields)
            return fields

        def skip(self, reason, **fields):
            return self.row(type="SKIP", status="SKIP", reason=reason,
                            **fields)

        def running(self):
            return self._alive

    # dry-run: enumerate only, nothing executed
    ctx = FakeCtx(dry=True)

    def boom(*_a, **_k):  # pragma: no cover — must never run
        raise AssertionError("dry-run must not execute commands")

    track_c.register(ctx, exec_fn=boom)
    assert len(ctx.rows) == 1
    assert ctx.rows[0]["type"] == "SKIP" and ctx.rows[0]["count"] == 12

    # wet run: lane rows mirror JSONL rows
    def handler(argv):
        if argv[:3] == ("git", "clone", "--depth=1"):
            return 128, "offline\n"
        return 0, "ok\n"

    ctx2 = FakeCtx()
    rows, summary = track_c.register(ctx2, exec_fn=Recorder(handler),
                                     clock=FakeClock())
    assert len(rows) == 12 and summary["fail_total"] == 0
    assert [r["type"] for r in ctx2.rows] == ["ci"] * 12 + ["summary"]
    assert {r["status"] for r in ctx2.rows} == {"PASS", "SKIP"}
    assert read_rows(tmp_path)[-1]["type"] == "summary"

    # stopped lane: the remainder is SKIPped, not executed
    calls = []

    def handler2(argv):
        calls.append(tuple(argv))
        return 0, "ok\n"

    ctx3 = FakeCtx(alive=False)
    rows3, summary3 = track_c.register(
        ctx3, exec_fn=Recorder(handler2), clock=FakeClock())
    assert calls == []
    assert all(r["status"] == "SKIP"
               and r["reason"] == "lane stopped: remainder skipped"
               for r in rows3)
    assert summary3["skip_total"] == 12

    lane = track_c.build_lane()
    assert lane.name == "track_c_host" and lane.window == "all_night"
    assert lane.cards == () and lane.needs_pcscd is False
    assert callable(lane.target)

    # sys.modules[name] = None makes `import name` raise ImportError
    monkeypatch.setitem(sys.modules, "overnight", None)
    lane2 = track_c.build_lane()
    assert (lane2.name, lane2.window, lane2.cards, lane2.needs_pcscd) == \
        (lane.name, lane.window, lane.cards, lane.needs_pcscd)
    assert lane2.target is lane.target
