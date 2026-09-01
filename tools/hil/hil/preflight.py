"""Composable pre-flight checks. Collect a report; hard fails abort the run."""

from dataclasses import dataclass, field
from typing import Callable
import subprocess

SEVERITY_FAIL = "fail"
SEVERITY_WARN = "warn"


@dataclass
class Check:
    name: str
    severity: str          # fail | warn
    ok: bool
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.ok or self.severity == SEVERITY_WARN


@dataclass
class Preflight:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, severity: str, ok: bool, detail: str = "") -> Check:
        c = Check(name=name, severity=severity, ok=ok, detail=detail)
        self.checks.append(c)
        return c

    @property
    def hard_failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == SEVERITY_FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == SEVERITY_WARN]

    def summary(self) -> str:
        lines = [f"  {c.severity.upper():4} {'PASS' if c.ok else 'FAIL'}  {c.name}"
                 + (f" — {c.detail}" if c.detail else "")
                 for c in self.checks]
        return "\n".join(lines)


def pcsc_readers() -> list[str]:
    """List pcscd reader names; empty list if pcscd is down."""
    code = (
        "from smartcard.System import readers; "
        "print('\\n'.join(str(r) for r in readers()))"
    )
    try:
        out = subprocess.run(
            ["python3", "-c", code], capture_output=True, text=True, timeout=10
        )
        if out.returncode != 0:
            return []
        return [l for l in out.stdout.splitlines() if l.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def console_ping(console_ctl: str) -> tuple[bool, str]:
    """PING the bolty console daemon; returns (alive, first_line)."""
    try:
        out = subprocess.run(
            ["python3", console_ctl, "PING"], capture_output=True, text=True, timeout=15
        )
        first = (out.stdout or out.stderr).splitlines()[0] if (out.stdout or out.stderr) else ""
        return out.returncode == 0 and first.startswith("alive"), first
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, str(e)


def check_readers(pf: Preflight, expect: dict[str, bool]) -> None:
    """expect: reader-substring -> required? (True=hard, False=warn-if-missing)."""
    readers = pcsc_readers()
    pf.add("pcscd-responding", SEVERITY_FAIL, bool(readers),
           f"{len(readers)} readers" if readers else "no readers / pcscd down")
    for needle, required in expect.items():
        found = [r for r in readers if needle.lower() in r.lower()]
        pf.add(f"reader:{needle}",
               SEVERITY_FAIL if required else SEVERITY_WARN,
               bool(found), found[0] if found else "not present")


def check_console(pf: Preflight, console_ctl: str) -> None:
    alive, detail = console_ping(console_ctl)
    pf.add("bolty-console-alive", SEVERITY_WARN, alive, detail)


def check_card(
    pf: Preflight,
    bolty_cli: str,
    expected_uid: str,
    registry_op: str,
    registry: "object",
    reader_needle: str | None = None,
) -> None:
    """Read the card UID via bolty-cli (auto-picks first reader with a card),
    enforce the registry, and assert the UID matches expectation."""
    from .cards import CardError  # local import to avoid cycle at module load

    try:
        registry.require(expected_uid, registry_op)
    except CardError as e:
        pf.add("card:registry", SEVERITY_FAIL, False, str(e))
        return

    card = registry.lookup(expected_uid)
    hint = reader_needle or card.reader_hint  # type: ignore[union-attr]
    readers = pcsc_readers()
    matching = [r for r in readers if hint.lower() in r.lower()] if hint != "any" else readers
    if hint != "any" and not matching:
        pf.add(f"card:{expected_uid}", SEVERITY_FAIL, False,
               f"hinted reader '{hint}' not present")
        return

    try:
        out = subprocess.run(
            [bolty_cli, "uid"], capture_output=True, text=True, timeout=30
        )
        uid_line = next(
            (l for l in out.stdout.splitlines() if l.startswith("UID:")), ""
        )
        actual = uid_line.split("UID:")[1].strip().lower() if uid_line else ""
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        pf.add(f"card:{expected_uid}", SEVERITY_FAIL, False, f"uid read failed: {e}")
        return

    if actual == expected_uid:
        pf.add(f"card:{expected_uid}", SEVERITY_FAIL, True,
               f"coupled on reader ({card.alias})" if card else "")  # type: ignore[arg-type]
    else:
        pf.add(f"card:{expected_uid}", SEVERITY_FAIL, False,
               f"expected {expected_uid}, got '{actual or 'no card'}'"
               " (intermittent coupling? reseat per lessons.md:180)")
