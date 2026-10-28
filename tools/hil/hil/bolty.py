"""bolty-cli runner: subprocess wrapper with timeout + structured errors.

Card coupling on the stick antenna is intermittent (documented in
lessons-learned.md B13/§180) — uid() retries once after a 2-second settle
before reporting failure, matching the "one retry after 2s always parses"
pattern from the role-switch boot-noise learnings (§178).
"""

import os
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONSOLE_CTL = REPO_ROOT / "tools" / "hil" / "bolty-ctl.py"

UID_RETRY_DELAY_S = 2.0


def _resolve_default_cli() -> Path:
    """Newest existing build among the checkout target dir and the shared
    ~/.cargo-target dir (ai-legion-small routes ALL cargo output there via
    ~/.cargo/config.toml — the in-tree target/debug/bolty-cli then goes
    STALE after rebuilds and the harness silently runs old code; caught
    live during the #233 hardware validation, 2026-10-28)."""
    candidates = [
        REPO_ROOT / "target" / "debug" / "bolty-cli",
        Path.home() / ".cargo-target" / "debug" / "bolty-cli",
    ]
    existing = [c for c in candidates if c.exists()]
    if not existing:
        return candidates[0]
    return max(existing, key=lambda c: c.stat().st_mtime)


DEFAULT_CLI = _resolve_default_cli()


class BoltyError(RuntimeError):
    def __init__(self, msg: str, returncode: int, stdout: str):
        super().__init__(msg)
        self.returncode = returncode
        self.stdout = stdout


@dataclass
class BoltyCli:
    binary: Path = DEFAULT_CLI
    timeout_s: int = 300
    reader: str | None = None

    def run(self, *args: str, timeout_s: int | None = None) -> str:
        """Run bolty-cli; return stdout; raise BoltyError on nonzero exit."""
        cmd = [str(self.binary), *args]
        env = dict(os.environ, BOLTY_READER=self.reader) if self.reader else None
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout_s or self.timeout_s, env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise BoltyError(f"bolty-cli {' '.join(args)} timed out", -1, "") from e
        if out.returncode != 0:
            raise BoltyError(
                f"bolty-cli {' '.join(args)} failed rc={out.returncode}:\n{out.stdout}{out.stderr}",
                out.returncode, out.stdout,
            )
        return out.stdout

    def uid(self, retries: int = 1) -> str:
        """Read the card UID; retry once after a settle delay on transient
        coupling failures (the documented intermittent-coupling pattern)."""
        last_err: Exception | None = None
        for attempt in range(1 + retries):
            if attempt > 0:
                time.sleep(UID_RETRY_DELAY_S)
            try:
                for line in self.run("uid", timeout_s=30).splitlines():
                    if line.startswith("UID:"):
                        return line.split("UID:")[1].strip().lower()
                last_err = BoltyError("uid command produced no UID line", 0, "")
            except BoltyError as e:
                last_err = e
        assert last_err is not None
        raise last_err

    def uid_or_none(self) -> str | None:
        """Read UID without raising; returns None on any failure."""
        try:
            return self.uid(retries=0)
        except (BoltyError, Exception):  # noqa: BLE001 — deliberate broad catch
            return None

    def readers_line(self) -> str:
        for line in self.run("uid", timeout_s=30).splitlines():
            if line.startswith("Connected to reader:"):
                return line.split("Connected to reader:")[1].strip()
        return "(unknown reader)"

    @staticmethod
    def expect_binary() -> None:
        if not DEFAULT_CLI.exists():
            raise BoltyError(
                f"bolty-cli binary missing at {DEFAULT_CLI} — run "
                "`cargo build -p bolty-cli` first", -1, ""
            )
