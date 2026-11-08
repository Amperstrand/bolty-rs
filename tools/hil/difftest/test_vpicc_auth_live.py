#!/usr/bin/env python3
"""LIVE auth gate: bolty-cli (the real ntag424 crate host stack)
authenticates against the vpicc MODEL over pcsc→vpcd.

Turns the 2026-10-31 one-off live proof (PR #264) into a permanent
bench gate: SELECT → AuthenticateEV2First Part1/Part2 → '✅ Key
accepted!', mutual session keys derived on both sides. Exercises the
FULL host stack — pcsc transport, bolty-cli reader selection, the
crate's handshake — against the card-side engine, with zero hardware.

Bench-host only (pcscd + vpcd table-card slot 35970, patched driver):
env_dependent skips it on CI runners. Requires a bolty-cli binary —
built on demand into this worktree's target dir (cached) or pointed at
via BOLTY_CLI.

vpcd hygiene (the 2026-10-31 debug arc): the FFCA reconnect desyncs the
vpcd IFD stream (stale ATR tail served as SW) — BOLTY_SKIP_FFCA_RECONNECT
+ BOLTY_UID_OVERRIDE are set, and the vpicc is started FRESH so the
driver's pipeline begins clean.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("Crypto", reason="pycryptodome: bench-host dep")

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

pytestmark = pytest.mark.env_dependent

GOLDEN = HERE / "results" / "golden_acr1252.json"
VPICC_PORT = 35970  # table-card vpcd slot (patched driver)
READER = "vPICC table card 00 00"
FACTORY_K0 = "00" * 16


def _bolty_cli() -> Path:
    env = os.environ.get("BOLTY_CLI")
    if env:
        p = Path(env)
        assert p.exists(), f"BOLTY_CLI={env} does not exist"
        return p
    # build on demand into this worktree (cargo-cached after the first run)
    repo = HERE.parents[2]  # tools/hil/difftest -> repo root
    # B35: ~/.cargo/config.toml redirects builds to /root/.cargo-target —
    # pin the target dir per-worktree or the binary lands elsewhere.
    env = dict(os.environ, CARGO_TARGET_DIR=str(repo / "target"))
    binp = repo / "target" / "debug" / "bolty-cli"
    if not binp.exists():
        subprocess.run(
            ["cargo", "build", "-p", "bolty-cli"],
            cwd=repo, check=True, capture_output=True, timeout=900, env=env)
    assert binp.exists(), "bolty-cli build produced no binary"
    return binp


def test_bolty_cli_authenticates_against_model():
    from vpicc_golden import GoldenVpicc
    from vpicc_model import ModelVpicc

    g = json.loads(GOLDEN.read_text())
    atr = (g.get("card_atr") or "").replace(" ", "")
    card = GoldenVpicc("127.0.0.1", VPICC_PORT, bytes.fromhex(atr),
                       answerer=ModelVpicc())
    card.start()
    try:
        deadline = time.time() + 60
        while not card.answered_probe.is_set() and time.time() < deadline:
            time.sleep(0.5)
        assert card.answered_probe.is_set(), "vpicc never answered ATR probe"

        env = dict(os.environ)
        env.update({
            "BOLTY_READER": READER,
            "BOLTY_SKIP_FFCA_RECONNECT": "1",   # FFCA reconnect desyncs vpcd
            "BOLTY_UID_OVERRIDE": "04c474fa967380",
        })
        r = subprocess.run(
            [str(_bolty_cli()), "try-key", "--key", FACTORY_K0],
            capture_output=True, text=True, timeout=180, env=env)
        out = r.stdout + r.stderr
        assert r.returncode == 0, f"try-key failed rc={r.returncode}: {out[-400:]}"
        assert "Key accepted" in out, f"no acceptance in output: {out[-400:]}"
        # the model must have completed a full handshake (session derived)
        engine = card.answerer.auth
        assert engine is not None and engine.session is not None, \
            "engine never derived a session — handshake incomplete"
        assert len(card.answerer.seen) >= 3, \
            "fewer than 3 exchanges reached the card"
    finally:
        card.stop()
