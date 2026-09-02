#!/usr/bin/env python3
"""Rig-lock status for `make status`: flock is advisory, so a leftover
.rig-lock FILE with no holder is normal — report whether the lock is
actually held, not whether the file exists."""

import fcntl
import sys
from pathlib import Path

LOCK = Path(__file__).resolve().parent / "results" / ".rig-lock"

try:
    f = LOCK.open("a+")
except OSError:
    print("none")
    sys.exit(0)

try:
    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("HELD by a session")
else:
    fcntl.flock(f, fcntl.LOCK_UN)
    print("free (stale file)")
