#!/usr/bin/env python3
"""Track C — CI-parity host-audit runner (plan todo 11).

Runs the exact CI command set of BOTH repos on the host, all night:

  bolty-rs (repo root):
    cargo fmt --check
    cargo clippy --workspace --exclude bolty-esp32 -- -D warnings
    cargo test --workspace --exclude bolty-esp32
    cargo test --package security-tests
    greatspectations spec-quote check (bolty-rs/AGENTS.md): a fresh
      depth-1 clone of https://github.com/boltcard/boltcard.git into a
      TEMP dir, then
      `python -m greatspectations check --config specquotes.toml
       --comment-start '// ' --comment-continue '//' -k <files>` where
      <files> is `git ls-files 'crates/bolty-core/src/*.rs'
      'crates/bolty-ntag/src/*.rs'`.  greatspectations resolves the
      config's relative `spec/...` source paths against the CONFIG
      file's directory, so specquotes.toml is copied UNCHANGED into the
      temp dir next to the clone — no repo working-tree pollution.
      If the clone fails (no network) the row is recorded as
      SKIP{reason:offline} and the audit continues.

  ccid-firmware-rs (repo root unless noted):
    cargo fmt --check
    RUSTFLAGS="-D warnings" cargo clippy --release
      --target thumbv7em-none-eabihf -- -D warnings        (default feats)
    RUSTFLAGS="-D warnings" cargo clippy --release
      --target thumbv7em-none-eabihf --no-default-features
      --features "stm32f746,profile-cherry-smartterminal-st2xxx"
      -- -D warnings
    cargo test --workspace --target x86_64-unknown-linux-gnu
    cargo test --target x86_64-unknown-linux-gnu   (cwd firmware/esp32-ccid)
    cargo test --features std --target x86_64-unknown-linux-gnu
                                                    (cwd vendor/iso14443-rs)
    scripts/verify-reproducibility.sh

Runner semantics: every command gets its own hard timeout (default
1800 s, enforced via subprocess timeout + process-group SIGKILL); each
result row {cmd, cwd, rc, duration_s, tail(last 80 lines)} is appended
INCREMENTALLY to track_c.jsonl (one JSON line per row, written the
moment the command finishes — a dead runner leaves a complete partial
audit); one FAIL never aborts the rest; a per-repo pass/fail/skip
summary closes the run.

Standalone:
  python3 tools/hil/overnight/track_c.py --list     # enumerated commands
  python3 tools/hil/overnight/track_c.py --quick    # fmt checks only
  python3 tools/hil/overnight/track_c.py            # full audit (default)
Integration: register(ctx) as a LaneSpec target (build_lane()).

The cargo-fuzz part of Track C lives in track_c_fuzz.py (todo 12 hook);
this runner is the CI-parity core and does not invoke cargo-fuzz.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "AuditCommand",
    "COMMANDS",
    "BOLTY_REPO",
    "CCID_REPO",
    "DEFAULT_TIMEOUT_S",
    "SPEC_URL",
    "select_commands",
    "print_command_list",
    "TrackC",
    "register",
    "build_lane",
    "main",
]

# ------------------------------------------------------------------ consts ----

HERE = Path(__file__).resolve().parent
BOLTY_REPO = HERE.parents[2]                # .../bolty-rs
CCID_REPO = HERE.parents[3] / "ccid-firmware-rs"

DEFAULT_TIMEOUT_S = 1800                    # plan todo 11: 30 min per command
TAIL_LINES = 80
JSONL_NAME = "track_c.jsonl"

SPEC_URL = "https://github.com/boltcard/boltcard.git"
GS_CONFIG = "specquotes.toml"
GS_LS_FILES_PATHSPECS = ("crates/bolty-core/src/*.rs", "crates/bolty-ntag/src/*.rs")
SPEC_QUOTE_DESC = (
    "git clone --depth=1 https://github.com/boltcard/boltcard.git <tmp>/spec && "
    "python -m greatspectations check --config specquotes.toml "
    "--comment-start '// ' --comment-continue '//' -k "
    "$(git ls-files 'crates/bolty-core/src/*.rs' 'crates/bolty-ntag/src/*.rs')"
)

_CLIPPY_CCID_BASE = (
    "cargo", "clippy", "--release", "--target", "thumbv7em-none-eabihf",
)
_RUSTFLAGS_DW = {"RUSTFLAGS": "-D warnings"}  # ccid AGENTS.md clippy passes


# ------------------------------------------------------------------ table ----


@dataclass(frozen=True)
class AuditCommand:
    """One CI-parity step: exact argv, explicit cwd, optional env overlay."""

    repo: str                     # "bolty-rs" | "ccid-firmware-rs"
    name: str                     # short id, e.g. "bolty/fmt"
    cwd: Path
    argv: tuple = ()              # empty for kind="spec_quote"
    env: dict | None = None       # merged over os.environ at exec time
    quick: bool = False           # included in the --quick (fmt-only) subset
    kind: str = "plain"           # "plain" | "spec_quote"
    display_override: str = ""

    @property
    def display(self) -> str:
        return self.display_override or _display(self.argv)


def _display(argv) -> str:
    return shlex.join([str(a) for a in argv])


COMMANDS: tuple[AuditCommand, ...] = (
    # -- bolty-rs (repo root) --
    AuditCommand("bolty-rs", "bolty/fmt", BOLTY_REPO,
                 ("cargo", "fmt", "--check"), quick=True),
    AuditCommand("bolty-rs", "bolty/clippy", BOLTY_REPO,
                 ("cargo", "clippy", "--workspace", "--exclude", "bolty-esp32",
                  "--", "-D", "warnings")),
    AuditCommand("bolty-rs", "bolty/test-workspace", BOLTY_REPO,
                 ("cargo", "test", "--workspace", "--exclude", "bolty-esp32")),
    AuditCommand("bolty-rs", "bolty/test-security", BOLTY_REPO,
                 ("cargo", "test", "--package", "security-tests")),
    AuditCommand("bolty-rs", "bolty/spec-quote", BOLTY_REPO,
                 kind="spec_quote", display_override=SPEC_QUOTE_DESC),
    # -- ccid-firmware-rs --
    AuditCommand("ccid-firmware-rs", "ccid/fmt", CCID_REPO,
                 ("cargo", "fmt", "--check"), quick=True),
    AuditCommand("ccid-firmware-rs", "ccid/clippy-f469", CCID_REPO,
                 (*_CLIPPY_CCID_BASE, "--", "-D", "warnings"),
                 env=dict(_RUSTFLAGS_DW)),
    AuditCommand("ccid-firmware-rs", "ccid/clippy-f746", CCID_REPO,
                 (*_CLIPPY_CCID_BASE, "--no-default-features",
                  "--features", "stm32f746,profile-cherry-smartterminal-st2xxx",
                  "--", "-D", "warnings"),
                 env=dict(_RUSTFLAGS_DW)),
    AuditCommand("ccid-firmware-rs", "ccid/test-workspace", CCID_REPO,
                 ("cargo", "test", "--workspace",
                  "--target", "x86_64-unknown-linux-gnu")),
    AuditCommand("ccid-firmware-rs", "ccid/test-esp32",
                 CCID_REPO / "firmware" / "esp32-ccid",
                 ("cargo", "test", "--target", "x86_64-unknown-linux-gnu")),
    AuditCommand("ccid-firmware-rs", "ccid/test-iso14443",
                 CCID_REPO / "vendor" / "iso14443-rs",
                 ("cargo", "test", "--features", "std",
                  "--target", "x86_64-unknown-linux-gnu")),
    AuditCommand("ccid-firmware-rs", "ccid/verify-reproducibility", CCID_REPO,
                 ("scripts/verify-reproducibility.sh",)),
)


def select_commands(commands=COMMANDS, quick: bool = False) -> tuple:
    """--quick subset: the two `cargo fmt --check` commands only."""
    if not quick:
        return tuple(commands)
    return tuple(c for c in commands if c.quick)


# ------------------------------------------------------------------ exec ----


def _subprocess_exec(argv, cwd, env, timeout_s):
    """Run argv under cwd with a hard timeout. Returns (rc, output, timed_out).

    The child gets its own process group (start_new_session) so a timeout
    SIGKILLs the whole tree; a killed child reports rc=-9 and timed_out=True.
    A missing executable reports rc=127 with the error text as output —
    recorded as a FAIL row, never an abort of the remaining commands.
    """
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.Popen(
            [str(a) for a in argv], cwd=cwd, env=full_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True)
    except OSError as e:
        return 127, f"spawn error: {e}\n", False
    try:
        out, _ = proc.communicate(timeout=timeout_s)
        return proc.returncode, out or "", False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, _ = proc.communicate()
        rc = proc.returncode if proc.returncode is not None else -9
        return rc, (out or "") + f"\n[track_c] timed out after {timeout_s}s", True


def _tail(out: str, lines: int = TAIL_LINES) -> str:
    return "\n".join(out.splitlines()[-lines:])


def _utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _default_results_dir() -> Path:
    return HERE / "results" / _utc_date()


def _append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(row) + "\n")


# ------------------------------------------------------------------ runner ----


class TrackC:
    """The CI-parity audit loop. exec_fn/clock are test seams (duck-typed)."""

    def __init__(self, commands=None, timeout_s: float = DEFAULT_TIMEOUT_S,
                 results_dir=None, exec_fn=None, clock=None):
        self.commands = tuple(commands) if commands is not None else COMMANDS
        self.timeout_s = float(timeout_s)
        self.results_dir = (Path(results_dir) if results_dir is not None
                            else _default_results_dir())
        self.exec_fn = exec_fn        # late-bound: None -> _subprocess_exec
        self.clock = clock or time    # needs .monotonic()

    # -- row helpers ----------------------------------------------------------

    def _row(self, cmd: AuditCommand, display: str, cwd, rc, out, dur,
             timed_out: bool, status: str = None, reason: str = None) -> dict:
        if status is None:
            status = "FAIL" if (rc != 0 or timed_out) else "PASS"
        row = {
            "repo": cmd.repo,
            "name": cmd.name,
            "cmd": display,
            "cwd": str(cwd),
            "rc": rc,
            "duration_s": round(dur, 3),
            "tail": _tail(out),
            "status": status,
            "timed_out": bool(timed_out),
        }
        if reason:
            row["reason"] = reason
        return row

    def _exec(self, argv, cwd, env=None):
        fn = self.exec_fn or _subprocess_exec
        started = self.clock.monotonic()
        rc, out, timed_out = fn(argv, cwd, env, self.timeout_s)
        return rc, out, timed_out, self.clock.monotonic() - started

    # -- spec-quote step (bolty-rs/AGENTS.md) ---------------------------------

    def _run_spec_quote(self, cmd: AuditCommand) -> dict:
        with tempfile.TemporaryDirectory(prefix="trackc-spec-") as td:
            tmp = Path(td)
            clone_argv = ("git", "clone", "--depth=1", SPEC_URL, str(tmp / "spec"))
            rc, out, timed_out, dur = self._exec(clone_argv, BOLTY_REPO)
            if timed_out:
                return self._row(cmd, _display(clone_argv), BOLTY_REPO, rc, out,
                                 dur, True, reason="spec clone timeout")
            if rc != 0:
                # skip-if-offline: an honest SKIP row beats a false FAIL
                return self._row(cmd, _display(clone_argv), BOLTY_REPO, rc, out,
                                 dur, False, status="SKIP", reason="offline")
            rc, out, timed_out, d = self._exec(
                ("git", "ls-files", *GS_LS_FILES_PATHSPECS), BOLTY_REPO)
            dur += d
            if timed_out or rc != 0:
                return self._row(cmd, "git ls-files " + " ".join(
                    GS_LS_FILES_PATHSPECS), BOLTY_REPO, rc, out, dur, timed_out,
                    reason="git ls-files failed")
            files = out.split()
            if not files:
                return self._row(cmd, "git ls-files " + " ".join(
                    GS_LS_FILES_PATHSPECS), BOLTY_REPO, rc, out, dur, False,
                    reason="no spec-quoted files enumerated")
            # greatspectations resolves relative source paths against the
            # CONFIG's directory — copy it unchanged next to the temp clone.
            shutil.copyfile(BOLTY_REPO / GS_CONFIG, tmp / GS_CONFIG)
            gs_argv = (sys.executable, "-m", "greatspectations", "check",
                       "--config", str(tmp / GS_CONFIG),
                       "--comment-start", "// ", "--comment-continue", "//",
                       "-k", *files)
            rc, out, timed_out, d = self._exec(gs_argv, BOLTY_REPO)
            dur += d
            return self._row(cmd, _display(gs_argv), BOLTY_REPO, rc, out, dur,
                             timed_out)

    def run_one(self, cmd: AuditCommand) -> dict:
        if cmd.kind == "spec_quote":
            return self._run_spec_quote(cmd)
        rc, out, timed_out, dur = self._exec(cmd.argv, cmd.cwd, cmd.env)
        return self._row(cmd, _display(cmd.argv), cmd.cwd, rc, out, dur,
                         timed_out)

    # -- the audit loop -------------------------------------------------------

    def run_audit(self, quick: bool = False, lane_row=None, running=None):
        """Run every selected command; persist each row the moment it lands.

        Returns (rows, summary). One FAIL (or timeout) never aborts the
        remaining commands; a stopped lane SKIPs its whole remainder.
        """
        selected = select_commands(self.commands, quick=quick)
        jsonl = self.results_dir / JSONL_NAME
        rows = []
        for i, cmd in enumerate(selected):
            if running is not None and not running():
                row = self._row(cmd, cmd.display, cmd.cwd, None, "", 0.0,
                                False, status="SKIP",
                                reason="lane stopped: remainder skipped")
            else:
                row = self.run_one(cmd)
            _append_jsonl(jsonl, row)
            if lane_row is not None:
                lane_row(type="ci", **_lane_fields(row))
            rows.append(row)
            print(f"[{i + 1}/{len(selected)}] {row['status']:<4} "
                  f"{row['name']} rc={row['rc']} {row['duration_s']}s")
        counts = {repo: {"pass": 0, "fail": 0, "skip": 0}
                  for repo in sorted({c.repo for c in selected})}
        for r in rows:
            counts[r["repo"]][r["status"].lower()] += 1
        summary = {
            "type": "summary",
            "repos": counts,
            "fail_total": sum(c["fail"] for c in counts.values()),
            "skip_total": sum(c["skip"] for c in counts.values()),
            "results_jsonl": str(jsonl),
        }
        _append_jsonl(jsonl, summary)
        if lane_row is not None:
            lane_row(type="summary", status="FAIL" if summary["fail_total"]
                     else "PASS", **_lane_fields(summary))
        for repo, c in counts.items():
            print(f"summary {repo}: pass={c['pass']} fail={c['fail']} "
                  f"skip={c['skip']}")
        print(f"rows: {jsonl}")
        return rows, summary


def _lane_fields(row: dict) -> dict:
    keep = ("repo", "name", "cmd", "cwd", "rc", "duration_s", "status",
            "reason", "timed_out", "repos", "fail_total", "skip_total",
            "results_jsonl")
    return {k: row[k] for k in keep if k in row}


# ---------------------------------------------------------- integration ----


def register(ctx, exec_fn=None, clock=None):
    """Lane target (todo-5 LaneSpec contract): run the Track C host audit.

    Rows land in the orchestrator's dated results dir (ctx.store.dir) both
    as lane rows (type "ci"/"summary", report-visible) and in the
    incrementally-appended track_c.jsonl. dry_run enumerates only.
    """
    store = getattr(ctx, "store", None)
    results_dir = Path(getattr(store, "dir", None) or _default_results_dir())
    tc = TrackC(results_dir=results_dir, exec_fn=exec_fn, clock=clock)
    if getattr(ctx, "dry_run", False):
        msg = (f"dry-run: track_c enumerated {len(tc.commands)} commands, "
               "none executed")
        skip = getattr(ctx, "skip", None)
        if callable(skip):
            skip(msg, count=len(tc.commands))
        else:
            ctx.row(type="SKIP", status="SKIP", reason=msg,
                    count=len(tc.commands))
        return None
    return tc.run_audit(lane_row=getattr(ctx, "row", None),
                        running=getattr(ctx, "running", None))


def build_lane():
    """LaneSpec for overnight.load_track_specs; duck-typed fallback when
    the orchestrator module is not importable (mirrors sibling tracks).

    The fallback also covers a shadowed import: when tools/hil/overnight/
    is a package (sibling __init__.py), `import overnight` under pytest
    resolves to that docstring-only package, which has no LaneSpec.
    """
    spec_cls = None
    try:
        import overnight
        spec_cls = getattr(overnight, "LaneSpec", None)
    except ImportError:
        pass
    if spec_cls is None:
        from types import SimpleNamespace
        return SimpleNamespace(name="track_c_host", target=register,
                               window="all_night", cards=(),
                               needs_pcscd=False, pace_s=1.0)
    return spec_cls("track_c_host", register, window="all_night",
                    cards=(), needs_pcscd=False, pace_s=1.0)


# ------------------------------------------------------------ selftest ----

SPEC_CMD_SELFTEST = next(c for c in COMMANDS if c.kind == "spec_quote")


def _selftest():  # pragma: no cover — exercised via CLI in tests
    """Offline self-test: table invariants, row classification, fail
    isolation, incremental JSONL, spec-quote offline SKIP — no cargo, no
    network (every exec goes through an injected fake exec_fn)."""
    import tempfile

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    class FakeClock:
        def __init__(self):
            self.t = 1000.0

        def monotonic(self):
            self.t += 1.0
            return self.t

    class FakeExec:
        """rc=1 when the marker arg is present; clone -> 128 (offline)."""

        def __init__(self, marker="--fail-me"):
            self.marker = marker
            self.calls = []

        def __call__(self, argv, cwd, env, timeout_s):
            self.calls.append(tuple(argv))
            if self.marker in argv:
                return 1, "simulated lint error\n", False
            if argv[:3] == ("git", "clone", "--depth=1"):
                return 128, "Could not resolve host\n", False
            return 0, "ok\n", False

    # table invariants (condensed todo-11 fixture)
    check("table_size", len(COMMANDS) == 12)
    check("table_repos", {c.repo for c in COMMANDS}
          == {"bolty-rs", "ccid-firmware-rs"})
    check("quick_fmt_only", [c.name for c in select_commands(quick=True)]
          == ["bolty/fmt", "ccid/fmt"])
    check("spec_kind", sum(1 for c in COMMANDS if c.kind == "spec_quote") == 1)

    # row classification: rc!=0 -> FAIL, rc=0 -> PASS, timed_out -> FAIL
    cmd = COMMANDS[0]
    tc0 = TrackC()
    r_fail = tc0._row(cmd, cmd.display, cmd.cwd, 1, "x", 1.0, False)
    r_pass = tc0._row(cmd, cmd.display, cmd.cwd, 0, "x", 1.0, False)
    r_to = tc0._row(cmd, cmd.display, cmd.cwd, 0, "x", 1.0, True)
    check("classify", (r_fail["status"], r_pass["status"], r_to["status"])
          == ("FAIL", "PASS", "FAIL"))

    # audit loop: one FAIL never aborts the rest; summary counts it;
    # every row lands in track_c.jsonl the moment it finishes
    with tempfile.TemporaryDirectory() as td:
        fail_cmd = AuditCommand("bolty-rs", "selftest/fail", BOLTY_REPO,
                                ("cargo", "fmt", "--check", "--fail-me"))
        fx = FakeExec()
        tc = TrackC(commands=(fail_cmd, COMMANDS[5]), exec_fn=fx,
                    results_dir=Path(td), clock=FakeClock())
        rows, summary = tc.run_audit()
        jsonl = [json.loads(line)
                 for line in (Path(td) / JSONL_NAME).read_text().splitlines()]
        check("fail_isolation", [r["status"] for r in rows]
              == ["FAIL", "PASS"] and len(fx.calls) == 2)
        check("summary_counts", summary["fail_total"] == 1
              and summary["repos"]["bolty-rs"]["fail"] == 1)
        check("jsonl_incremental", len(jsonl) == 3
              and jsonl[-1]["type"] == "summary")

        # spec-quote offline: clone rc!=0 -> SKIP{reason:offline}, not FAIL
        tc2 = TrackC(exec_fn=FakeExec(), results_dir=Path(td),
                     clock=FakeClock())
        spec = tc2.run_one(SPEC_CMD_SELFTEST)
        check("spec_offline_skip", spec["status"] == "SKIP"
              and spec["reason"] == "offline")

    ok = all(c for _, c in checks)
    for name, cond in checks:
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    print(f"selftest: {sum(c for _, c in checks)}/{len(checks)} checks, "
          f"{'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


# -------------------------------------------------------------- CLI ----


def print_command_list(commands=COMMANDS) -> None:
    print(f"track_c host-audit command list ({len(commands)}):")
    for i, c in enumerate(commands, 1):
        quick = "  (quick)" if c.quick else ""
        print(f"  [{i:>2}] {c.repo:<16} {c.name:<28} cwd={c.cwd}")
        print(f"        $ {c.display}{quick}")


def main(argv=None) -> int:  # pragma: no cover — thin CLI over TrackC
    ap = argparse.ArgumentParser(
        description="Track C: CI-parity host-audit runner (both repos)")
    ap.add_argument("--selftest", action="store_true",
                    help="offline table/classification/persistence self-test")
    ap.add_argument("--list", action="store_true",
                    help="print the enumerated command list and exit")
    ap.add_argument("--quick", action="store_true",
                    help="fmt checks only (the two cargo fmt --check runs)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S,
                    help=f"per-command timeout seconds "
                         f"(default {DEFAULT_TIMEOUT_S})")
    ap.add_argument("--results-dir", type=Path, default=None,
                    help="directory for track_c.jsonl "
                         f"(default {_default_results_dir()})")
    args = ap.parse_args(argv)
    if args.selftest:
        return _selftest()
    if args.list:
        print_command_list(COMMANDS)
        return 0
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    tc = TrackC(timeout_s=args.timeout, results_dir=args.results_dir)
    _, summary = tc.run_audit(quick=args.quick)
    return 0 if summary["fail_total"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
