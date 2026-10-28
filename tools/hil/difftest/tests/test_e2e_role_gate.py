"""Owner-approval gate for M5Stick role-switching (issue #178, e2e.py).

The gate is fail-closed: only --yes / BOLTY_DIFFTEST_YES / an interactive
confirmation approve. Everything else — non-tty stdin (CI, cron, pipes),
EOF, a wrong confirmation word — must REFUSE, and a refused switch must
never invoke role_switch.py (the reflash).
"""

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # difftest/, where e2e lives

import e2e  # noqa: E402
import pytest  # noqa: E402


class _FakeTty(io.StringIO):
    def isatty(self):
        return True


class _NotATty(io.StringIO):
    def isatty(self):
        return False


def _no_env(monkeypatch):
    monkeypatch.delenv("BOLTY_DIFFTEST_YES", raising=False)


# ------------------------------------------------------------- gate ----

def test_gate_refuses_without_any_approval(monkeypatch):
    _no_env(monkeypatch)
    assert e2e.owner_approved_role_switch(
        stdin=_NotATty(), env={}) is False


def test_gate_refuses_on_noninteractive_stdin_even_with_tty_words(monkeypatch):
    # A piped stdin carrying the right word is NOT approval (#178:
    # scripted runs must pass --yes / env — no echo-into-stdin bypass).
    _no_env(monkeypatch)
    assert e2e.owner_approved_role_switch(
        stdin=io.StringIO("switch\n"), env={}) is False


def test_gate_env_var_approves(monkeypatch):
    assert e2e.owner_approved_role_switch(
        stdin=_NotATty(), env={"BOLTY_DIFFTEST_YES": "1"}) is True
    assert e2e.owner_approved_role_switch(
        stdin=_NotATty(), env={"BOLTY_DIFFTEST_YES": "yes"}) is True


def test_gate_env_var_zero_and_empty_do_not_approve():
    assert e2e.owner_approved_role_switch(
        stdin=_NotATty(), env={"BOLTY_DIFFTEST_YES": "0"}) is False
    assert e2e.owner_approved_role_switch(
        stdin=_NotATty(), env={"BOLTY_DIFFTEST_YES": ""}) is False


def test_gate_assume_yes_beats_noninteractive_stdin():
    assert e2e.owner_approved_role_switch(
        assume_yes=True, stdin=_NotATty(), env={}) is True


def test_gate_interactive_confirmation_word(monkeypatch):
    _no_env(monkeypatch)
    assert e2e.owner_approved_role_switch(
        stdin=_FakeTty("switch\n"), env={}) is True


def test_gate_interactive_wrong_word_refuses(monkeypatch):
    _no_env(monkeypatch)
    assert e2e.owner_approved_role_switch(
        stdin=_FakeTty("y\n"), env={}) is False
    assert e2e.owner_approved_role_switch(
        stdin=_FakeTty(""), env={}) is False  # EOF


# ------------------------------------------------------ phase_switch ----

def test_phase_switch_refused_never_invokes_role_switch(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(e2e, "run", lambda *a, **k: calls.append(a) or (1, ""))
    monkeypatch.delenv("BOLTY_DIFFTEST_YES", raising=False)
    monkeypatch.setattr(e2e, "owner_approved_role_switch",
                        lambda assume_yes=False: False)
    result = e2e.phase_switch("ccid")
    assert result["status"] == "REFUSED"
    assert calls == [], "the reflash must never run when the gate refuses"
    out = capsys.readouterr().out
    assert "owner approval" in out


def test_phase_switch_approved_runs_role_switch(monkeypatch):
    calls = []
    monkeypatch.setattr(
        e2e, "run",
        lambda cmd, **k: calls.append(cmd) or (0, "ok=True detail=verified"))
    monkeypatch.setattr(e2e, "owner_approved_role_switch",
                        lambda assume_yes=False: True)
    result = e2e.phase_switch("ccid", assume_yes=True)
    assert result["status"] == "PASS"
    assert calls and "role_switch" in " ".join(calls[0])
