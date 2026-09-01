"""bolty-cli runner: subprocess wrapper with timeout + structured errors."""

import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CLI = REPO_ROOT / "target" / "debug" / "bolty-cli"
DEFAULT_CONSOLE_CTL = REPO_ROOT / "tools" / "hil" / "bolty-ctl.py"


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

    def uid(self) -> str:
        for line in self.run("uid", timeout_s=30).splitlines():
            if line.startswith("UID:"):
                return line.split("UID:")[1].strip().lower()
        raise BoltyError("uid command produced no UID line", 0, "")

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
