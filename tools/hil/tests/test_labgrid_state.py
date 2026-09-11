"""note_rig_state unit tests: tag construction + the best-effort contract.

Pattern 15 (docs/labgrid-bench-sharing.md P1): a coordinator hiccup must
never kill a run — every failure mode (client missing, timeout, coordinator
down) is swallowed. Pure logic, no hardware.
"""

import re
import subprocess

from hil.labgrid_state import (
    COORDINATOR, FALLBACK_CLIENT, PLACE, build_tags, note_rig_state,
)


class FakeRunner:
    def __init__(self, exc: Exception | None = None):
        self.calls: list[tuple[list[str], dict]] = []
        self.exc = exc

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(argv, 0)


def test_build_tags_format():
    tags = build_tags("difftest:apdu", firmware="06fd7912", owner="bolty-rs")
    assert tags[:3] == ["firmware=06fd7912", "test=difftest:apdu",
                        "owner=bolty-rs"]
    assert re.fullmatch(r"ts=\d{8}T\d{6}", tags[3]), tags[3]
    assert len(tags) == 4


def test_build_tags_defaults():
    tags = build_tags("t", now=0)
    assert tags[0] == "firmware=-"
    assert tags[1] == "test=t"
    assert tags[2] == "owner=bolty-rs"
    assert re.fullmatch(r"ts=\d{8}T\d{6}", tags[3])


def test_note_rig_state_sets_place_tags(monkeypatch):
    monkeypatch.setattr("hil.labgrid_state.shutil.which", lambda _: None)
    fake = FakeRunner()
    note_rig_state("pytest:hil", firmware="abc123", _run=fake)
    argv, kwargs = fake.calls[0]
    assert argv[:9] == [FALLBACK_CLIENT, "-x", COORDINATOR, "-p", PLACE,
                        "set-tags", "firmware=abc123", "test=pytest:hil",
                        "owner=bolty-rs"]
    assert len(argv) == 10 and re.fullmatch(r"ts=\d{8}T\d{6}", argv[9])
    assert kwargs["timeout"] == 5
    assert kwargs["capture_output"] is True


def test_note_rig_state_prefers_path_client(monkeypatch):
    monkeypatch.setattr("hil.labgrid_state.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    fake = FakeRunner()
    note_rig_state("t", _run=fake)
    assert fake.calls[0][0][0] == "labgrid-client"


def test_note_rig_state_swallows_all_failures():
    for exc in (subprocess.TimeoutExpired("labgrid-client", 5),
                FileNotFoundError("labgrid-client not found"),
                OSError("coordinator unreachable"),
                RuntimeError("surprise")):
        note_rig_state("t", _run=FakeRunner(exc=exc))  # must not raise


def test_note_rig_state_ignores_nonzero_rc():
    # set-tags failing at the coordinator (e.g. place wiped by a restart)
    # is a plain nonzero exit, not an exception — also never fatal.
    note_rig_state("t", _run=lambda *a, **k: subprocess.CompletedProcess(a[0], 1))
