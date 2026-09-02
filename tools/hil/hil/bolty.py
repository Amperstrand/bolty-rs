"""bolty-cli runner: subprocess wrapper with timeout + structured errors.

Card coupling on the stick antenna is intermittent (documented in
lessons-learned.md B13/§180) — uid() retries once after a 2-second settle
before reporting failure, matching the "one retry after 2s always parses"
pattern from the role-switch boot-noise learnings (§178).
"""

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CLI = REPO_ROOT / "target" / "debug" / "bolty-cli"
DEFAULT_CONSOLE_CTL = REPO_ROOT / "tools" / "hil" / "bolty-ctl.py"

UID_RETRY_DELAY_S = 2.0


class BoltyError(RuntimeError):
    def __init__(self, msg: str, returncode: int, stdout: str):
        super().__init__(msg)
        self.returncode = returncode
        self.stdout = stdout


@dataclass
class BoltyCli:
    binary: Path = DEFAULT_CLI
    timeout_s: int = 300

    def run(self, *args: str, timeout_s: int | None = None) -> str:
        """Run bolty-cli; return stdout; raise BoltyError on nonzero exit."""
        cmd = [str(self.binary), *args]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout_s or self.timeout_s,
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
