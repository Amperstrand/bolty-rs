#!/usr/bin/env python3
"""Minimal bolty-console unix-socket client (overnight Track A helper).

Protocol (tools/hil/bolty-console.py:91-137): one command per connection;
the daemon collects the console reply until 1.0s quiescence (40s cap),
appends an ``OK ...`` line and closes the connection. ``PING`` answers from
daemon state only and never writes to the serial port; ``RAW <sec>`` is
passive capture.

This module NEVER opens the serial device itself — only the daemon holds
the port (B11 FT232 wedge; see tools/hil/bolty-console.py docstring). The
socket round-trip pattern mirrors tools/hil/bolty-ctl.py.
"""

import re
import socket

__all__ = ["DEFAULT_SOCKET", "ConsoleError", "send_raw", "console_cmd", "ping"]

DEFAULT_SOCKET = "/run/bolty/console.sock"


class ConsoleError(OSError):
    """Console socket transport failure (unreachable/timeout/broken)."""


def _roundtrip(sock_path, payload, timeout):
    """One command over one connection; returns the full response text."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(payload)
        chunks = []
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout as exc:
                raise ConsoleError(
                    f"console socket {sock_path!r} timeout after {timeout}s"
                ) from exc
            if not c:
                break
            chunks.append(c)
    except OSError as exc:
        raise ConsoleError(f"console socket {sock_path!r}: {exc!r}") from exc
    finally:
        try:
            s.close()
        except OSError:
            pass
    return b"".join(chunks).decode("latin1", "replace")


def send_raw(sock_path, payload, timeout=70.0):
    """Send ONE raw console line (bytes; used by the fuzzer). Newlines are
    collapsed so the daemon's split(b"\\n", 1) keeps single-line semantics."""
    line = bytes(payload).replace(b"\n", b"\x0b").rstrip(b"\r") + b"\n"
    return _roundtrip(sock_path, line, timeout)


def console_cmd(sock_path, cmd, timeout=70.0, expect_ok=True):
    """Send a plain-text console command; verify the trailing OK line."""
    text = _roundtrip(sock_path, str(cmd).encode("latin1", "replace") + b"\n",
                      timeout)
    if expect_ok:
        lines = text.splitlines()
        if not lines or not lines[-1].startswith("OK"):
            raise ConsoleError(f"console command {cmd!r} failed: {text!r}")
    return text


def ping(sock_path, timeout=5.0):
    """Daemon PING (never touches the tty). Same result shape as
    overnight.ping_daemon: {"hb_age": int|None, "lines": [...], "error": ...}."""
    try:
        text = _roundtrip(sock_path, b"PING\n", timeout)
    except ConsoleError as exc:
        return {"hb_age": None, "lines": [], "error": str(exc)}
    m = re.search(r"hb_age=(-?\d+)s", text)
    return {"hb_age": int(m.group(1)) if m else None,
            "lines": text.splitlines(), "error": None}
