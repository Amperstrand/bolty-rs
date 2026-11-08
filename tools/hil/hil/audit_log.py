"""Parse the shared forensic audit log (default /tmp/bolty-audit.log).

The log is append-only and multi-writer. Two real-world corruption
classes exist (issue #256, evidence from 2026-10-19):

- PROSE POLLUTION: lane/harness scripts have appended reader tables and
  labgrid reservation dumps — untimestamped, multi-line prose — directly
  into the log.
- GLUED ENTRIES: concurrent writers appending without interlocking can
  emit two entries on one physical line, e.g.
  ``[ts] EVENT a [provenance=X][ts2] EVENT b`` (seen repeatedly in the
  2026-10-19 parallel-test bursts).

``iter_entries`` tolerates both: it yields every well-formed entry
``(ts_ms, text)``, splitting glued runs wherever a new
``[epoch-ms] `` token starts, and silently skips prose-only stretches.
Forensic readers should use this instead of raw line iteration so the
pollution classes cannot fake or hide entries.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

# Epoch-ms timestamps are 13 digits until the year 2286.
_TOKEN = re.compile(r"\[(\d{13})\] ")


def iter_entries(path) -> Iterator[tuple[int, str]]:
    """Yield (ts_ms, text) for every well-formed audit entry in file
    order, splitting glued entries on one physical line. Prose-only
    stretches (reader tables, labgrid dumps) yield nothing."""
    data = Path(path).read_text(errors="replace")
    parts = _TOKEN.split(data)
    # split() with one capture group yields:
    # [leading_prose?, ts1, text1, ts2, text2, ..., trailing?]
    for i in range(1, len(parts) - 1, 2):
        yield int(parts[i]), parts[i + 1].rstrip("\n")


def stats(path) -> dict:
    """Entry count + prose-only line count, for hygiene reporting."""
    entries = sum(1 for _ in iter_entries(path))
    prose_lines = sum(
        1
        for line in Path(path).read_text(errors="replace").splitlines()
        if not _TOKEN.search(line)
    )
    return {"entries": entries, "prose_lines": prose_lines}


def entries_matching(path, needle: str) -> list[tuple[int, str]]:
    """Case-insensitive substring search across well-formed entries."""
    n = needle.lower()
    return [(ts, t) for ts, t in iter_entries(path) if n in t.lower()]
