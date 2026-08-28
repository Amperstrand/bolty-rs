#!/usr/bin/env python3
"""Track A OTA-negative suite (plan todo 9, overnight-ccid-bolty-audit).

Three device-side negative OTA cases, all served from a LOCAL HTTP server
on loopback/LAN and all expecting the device to REJECT the update and stay
on the factory slot:

  (a) wrong_signature   — full image download, signature from a FRESH
                          throwaway Ed25519 key (ota-sign.py keygen+sign);
                          never the device NVS otakey, never ota_sig.hex
                          (that file holds the VALID signature).
  (b) truncated_download— handler declares full Content-Length, closes the
                          connection after ~40% of the bytes.
  (c) http_404          — image URL that 404s.

Evidence is the RAW console capture during the download window: the device
prints the OtaError Display strings (apps/bolty-esp32/src/ota.rs) on the
serial console as ``[FAIL] <message>`` lines. At least one rejection
marker must appear and no committing marker may appear; ``ver`` must be
identical before/after, PING alive, next HB within 30s.

Capability gate: the ``ota`` console command only exists in builds with
the ``ota`` feature and a provisioned otakey lives in NVS (wiped by every
merged-image reflash — provisioning is todo 18's job AFTER the final
flash). If ``ota`` is absent from ``help`` the whole track records one
honest SKIP row instead of failing.

Standalone (no device):   python3 track_a_ota.py --selftest
Lane integration:         register(ctx)   # duck-typed PhaseContext (todo 5)
"""

import argparse
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SIGN_TOOL = REPO_ROOT / "tools" / "ota-sign.py"
CONSOLE_SOCK = "/run/bolty/console.sock"
DEFAULT_IMAGE = Path.home() / "fw-backup" / "bolty-esp32-ota-image-20260827.bin"
VALID_SIG_FILE = Path.home() / "fw-backup" / "ota_sig.hex"
DEFAULT_WORKDIR = Path(__file__).resolve().parent / "results" / "ota_tmp"

CASE_TIMEOUT_S = 120
MAX_ATTEMPTS = 2
HB_MAX_AGE_S = 30
TRUNCATED_PCT = 40
RAW_WINDOWS_PER_ATTEMPT = 3

REJECTION_MARKERS = (
    "signature verification FAILED",
    "http status ",
    "http: ",
    "empty firmware image",
)
COMMIT_MARKERS = (
    "signature VERIFIED",
    "committing",
    "ota complete",
    "rebooting",
)
UNPROVISIONED_MARKER = "not provisioned"

CASES = (
    ("wrong_signature", "/fw.bin", "normal"),
    ("truncated_download", "/trunc.bin", "truncated"),
    ("http_404", "/missing.bin", "404"),
)


class ConsoleError(RuntimeError):
    pass


class OtaCapabilityError(RuntimeError):
    pass


class SignatureError(RuntimeError):
    pass


# ---------------------------------------------------------------- console ----


class ConsoleClient:
    """bolty-console unix-socket client (protocol: bolty-console.py:91-137)."""

    def __init__(self, sock_path=CONSOLE_SOCK):
        self._sock_path = sock_path

    def _request(self, payload, timeout):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self._sock_path)
            s.sendall((payload + "\n").encode())
            chunks = []
            while True:
                c = s.recv(4096)
                if not c:
                    break
                chunks.append(c)
        finally:
            s.close()
        lines = b"".join(chunks).decode("latin1", "replace").splitlines()
        if not lines or not lines[-1].startswith("OK"):
            raise ConsoleError(f"daemon rejected {payload.split()[0]!r}: "
                               f"{lines[-1] if lines else 'no reply'}")
        return lines[:-1]

    def cmd(self, line, timeout=30.0):
        return self._request(line, timeout)

    def raw(self, secs):
        return self._request(f"RAW {secs}", timeout=secs + 10)


# ------------------------------------------------------------ lan address ----


def resolve_lan_ip():
    """Host LAN IP via a sendless UDP connect; None if undeterminable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.13.1", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


# ----------------------------------------------------------------- server ----


class LocalOtaServer:
    """One-shot local OTA image server: normal / truncated / 404 handlers.

    Serves ONLY on loopback or the host's LAN IP (never 0.0.0.0). Each
    ``arm(path, mode)`` primes exactly one image-serving; a re-fetch of a
    consumed or un-armed path 404s, so a device retry can never pull the
    image twice by accident.
    """

    LOOPBACK = ("127.0.0.1", "::1", "localhost")

    def __init__(self, host, image_path, port=0):
        allowed = set(self.LOOPBACK)
        lan = resolve_lan_ip()
        if lan:
            allowed.add(lan)
        if host not in allowed:
            raise ValueError(
                f"refusing to bind OTA server on {host!r} "
                f"(not loopback/LAN {sorted(allowed)})")
        self.host = host
        self._port = port
        self._image = Path(image_path).read_bytes()
        self._lock = threading.Lock()
        self._armed = None
        self.requests = []
        self.served_count = 0
        self.served_bytes = 0
        self.declared_length = 0
        self._httpd = None
        self._thread = None

    def arm(self, path, mode):
        with self._lock:
            self._armed = {"path": path, "mode": mode, "consumed": False}

    def url(self, path):
        host = self.host if ":" not in self.host else f"[{self.host}]"
        return f"http://{host}:{self._httpd.server_port}{path}"

    def start(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                with server._lock:
                    armed = dict(server._armed) if server._armed else None
                    hit = (armed and not armed["consumed"]
                           and self.path == armed["path"])
                    if hit:
                        server._armed["consumed"] = True
                mode = armed["mode"] if hit else None
                if not hit:
                    self._journal(served=False)
                    self.send_error(404)
                    return
                if mode == "404":
                    self._journal(served=False)
                    self.send_error(404)
                    return
                n = len(server._image)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(n))
                self.end_headers()
                if mode == "truncated":
                    body = server._image[:n * TRUNCATED_PCT // 100]
                else:
                    body = server._image
                self.wfile.write(body)
                self.wfile.flush()
                self.close_connection = True
                with server._lock:
                    server.served_count += 1
                    server.declared_length = n
                    server.served_bytes = len(body)
                self._journal(served=True, mode=mode)

            def _journal(self, served, mode=None):
                with server._lock:
                    server.requests.append(
                        {"t": time.monotonic(), "path": self.path,
                         "mode": mode, "served": served})

        self._httpd = ThreadingHTTPServer((self.host, self._port), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None


# -------------------------------------------------------- signature attack ----

_valid_sig_cache = None


def _valid_sig_hex():
    global _valid_sig_cache
    if _valid_sig_cache is None:
        try:
            _valid_sig_cache = VALID_SIG_FILE.read_text().strip()
        except OSError:
            _valid_sig_cache = ""
    return _valid_sig_cache


class SignatureFactory:
    """WRONG-signature generator: throwaway key, never the device otakey.

    keygen+sign run against a fresh PEM under the (gitignored) workdir;
    the pubkey never leaves the host, so device NVS is untouched. The
    output is validated as 128-hex and must differ from ota_sig.hex (the
    VALID signature — serving it would make case (a) a positive OTA).
    """

    def __init__(self, repo_root, workdir):
        self._tool = Path(repo_root) / "tools" / "ota-sign.py"
        self._workdir = Path(workdir)

    def wrong_signature(self, firmware_path):
        self._workdir.mkdir(parents=True, exist_ok=True)
        privkey = self._workdir / "throwaway-ota-key.pem"
        self._run(["keygen", "--privkey", str(privkey)])
        out = self._run(["sign", "--privkey", str(privkey),
                         "--firmware", str(firmware_path)])
        return self._extract_signature(out)

    def _run(self, args):
        proc = subprocess.run(
            [sys.executable, str(self._tool), *args],
            capture_output=True, text=True, timeout=60, cwd=str(REPO_ROOT))
        if proc.returncode != 0:
            raise SignatureError(
                f"ota-sign.py {args[0]} rc={proc.returncode}: "
                f"{proc.stderr.strip()[:200]}")
        return proc.stdout

    def _extract_signature(self, stdout):
        for line in stdout.splitlines():
            if not line.startswith("Signature: "):
                continue
            sig = line[len("Signature: "):].strip()
            if not re.fullmatch(r"[0-9a-f]{128}", sig):
                raise SignatureError(f"signature is not 128-hex: {sig[:40]}…")
            if sig == _valid_sig_hex():
                raise SignatureError(
                    "refusing to return the VALID device signature "
                    "(ota_sig.hex) — positives are out of scope")
            return sig
        raise SignatureError("no 'Signature:' line in ota-sign.py output")

    def wipe(self):
        shutil.rmtree(self._workdir, ignore_errors=True)


# ----------------------------------------------------------- evidence parse ----


def parse_rejection_evidence(lines):
    """Split console lines into (rejection_lines, committing_lines).

    A PASS needs >=1 rejection and 0 committing lines. 'OTA signing key
    not provisioned' is deliberately NOT a rejection marker: it means NVS
    was wiped by a reflash (an environment problem, not proof the
    signature-verification path rejected anything) and maps to a SKIP.
    """
    rejection = [ln for ln in lines
                 if any(m in ln for m in REJECTION_MARKERS)]
    commit = [ln for ln in lines
              if any(m in ln for m in COMMIT_MARKERS)]
    return rejection, commit


def find_unprovisioned(lines):
    return [ln for ln in lines if UNPROVISIONED_MARKER in ln]


# --------------------------------------------------------- capability gate ----


def capability_gate(ctx, console):
    """True iff the console `help` lists the `ota` command; else SKIP row."""
    try:
        text = "\n".join(console.cmd("help"))
    except Exception as e:  # noqa: BLE001 — any console failure is a gate fail
        raise OtaCapabilityError(f"console unreachable: {e}") from e
    if not re.search(r"\bota\b", text, re.IGNORECASE):
        ctx.skip("'ota' command absent from console help — OTA feature not "
                 "in this build; OTA negatives not exercised (honest "
                 "degradation)", track="a_ota")
        return False
    return True


# ------------------------------------------------------------- case runner ----


class CaseRunner:
    def __init__(self, console, ctx, clock=None):
        self._console = console
        self._ctx = ctx
        self._clock = clock or time

    def run_case(self, name, url, sig):
        t0 = self._clock.monotonic()
        deadline = t0 + CASE_TIMEOUT_S
        base = {"type": "ota_negative", "case": name, "url": url}
        try:
            ver_before = self._console.cmd("ver")
        except Exception as e:  # noqa: BLE001 — row must record, not crash
            return self._fail(base, f"ver-before unreachable: {e}", [], t0)

        evidence, rej, commit, unprov = [], [], [], []
        attempts = 0
        for attempt in range(MAX_ATTEMPTS):
            attempts = attempt + 1
            try:
                evidence = self._collect_evidence(url, sig, deadline)
            except (TimeoutError, ConsoleError, OSError) as e:
                evidence, rej, commit = [], [], []
                if self._clock.monotonic() >= deadline or \
                        attempt == MAX_ATTEMPTS - 1:
                    return self._fail(base, f"transport failure: {e}",
                                      evidence, t0, attempts)
                continue
            rej, commit = parse_rejection_evidence(evidence)
            unprov = find_unprovisioned(evidence)
            if commit or rej or unprov:
                break

        if commit:
            return self._fail(base, "device COMMITTED an update during a "
                              "negative case: " + " | ".join(commit),
                              evidence, t0, attempts)
        if unprov:
            reason = ("otakey not provisioned on device (NVS wiped by "
                      "reflash?) — signature path not exercised")
            self._ctx.skip(reason, case=name, url=url, evidence=evidence)
            return {**base, "status": "SKIP", "reason": reason,
                    "attempts": attempts, "evidence": evidence}
        if not rej:
            why = ("case budget exhausted" if self._clock.monotonic() >=
                   deadline else "no rejection marker in console output")
            return self._fail(base, why, evidence, t0, attempts)

        try:
            ver_after = self._console.cmd("ver")
        except Exception as e:  # noqa: BLE001
            return self._fail(base, f"ver-after unreachable: {e}",
                              evidence, t0, attempts)
        if [ln.rstrip() for ln in ver_after] != [ln.rstrip() for ln in ver_before]:
            return self._fail(base, "console 'ver' output changed across the "
                              "rejected OTA attempt (device was modified)",
                              evidence, t0, attempts)
        try:
            ping = "\n".join(self._console.cmd("PING"))
        except Exception as e:  # noqa: BLE001
            return self._fail(base, f"PING unreachable: {e}",
                              evidence, t0, attempts)
        if "alive" not in ping:
            return self._fail(base, "PING not alive after rejected OTA",
                              evidence, t0, attempts)
        m = re.search(r"hb_age=(-?\d+)s", ping)
        if m and int(m.group(1)) > HB_MAX_AGE_S:
            return self._fail(base, f"heartbeat stale: hb_age={m.group(1)}s "
                              f"> {HB_MAX_AGE_S}s", evidence, t0, attempts)
        return self._ctx.row(**base, status="PASS", attempts=attempts,
                             evidence=rej,
                             duration_s=round(self._clock.monotonic() - t0, 1))

    def _collect_evidence(self, url, sig, deadline):
        remaining = deadline - self._clock.monotonic()
        evidence = self._console.cmd(f"ota {url} {sig}",
                                     timeout=min(remaining, CASE_TIMEOUT_S) + 5)
        for _ in range(RAW_WINDOWS_PER_ATTEMPT):
            rej, commit = parse_rejection_evidence(evidence)
            if rej or commit or find_unprovisioned(evidence):
                return evidence
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                break
            evidence += self._console.raw(min(10.0, remaining))
        return evidence

    def _fail(self, base, reason, evidence, t0, attempts=0):
        return self._ctx.row(**base, status="FAIL", fail_reason=reason,
                             evidence=evidence,
                             attempts=attempts,
                             duration_s=round(self._clock.monotonic() - t0, 1))


# -------------------------------------------------------------- lane entry ----


def register(ctx, console=None, image_path=None, sig_factory=None):
    """Lane entry (duck-typed PhaseContext from overnight.py todo 5)."""
    if getattr(ctx, "dry_run", False):
        for name, _, _ in CASES:
            ctx.row(type="ota_negative", case=name, status="PASS",
                    simulated=True)
        return
    try:
        if not capability_gate(ctx, console or ConsoleClient()):
            return
    except OtaCapabilityError as e:
        ctx.skip(f"OTA capability probe failed: {e}", track="a_ota")
        return
    image = Path(image_path) if image_path else DEFAULT_IMAGE
    if not image.exists():
        ctx.skip(f"OTA image missing: {image}", track="a_ota")
        return
    factory = sig_factory or SignatureFactory(REPO_ROOT, DEFAULT_WORKDIR)
    server = LocalOtaServer(host=resolve_lan_ip() or "127.0.0.1",
                            image_path=image)
    runner = CaseRunner(console or ConsoleClient(), ctx)
    try:
        sig = factory.wrong_signature(image)
        server.start()
        for name, path, mode in CASES:
            if not ctx.running():
                break
            server.arm(path, mode)
            runner.run_case(name, url=server.url(path), sig=sig)
            ctx.sleep(2)
    finally:
        server.stop()
        factory.wipe()


# --------------------------------------------------------------- selftest ----


def selftest():
    with tempfile.TemporaryDirectory(prefix="ota-selftest-") as td:
        image = Path(td) / "fw.bin"
        image.write_bytes(b"\x5a" * 1000)
        checks = []

        def check(name, ok, detail=""):
            checks.append((name, ok, detail))
            print(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}")

        srv = LocalOtaServer(host="127.0.0.1", image_path=image)
        srv.arm("/fw.bin", "normal")
        srv.start()
        try:
            with urllib.request.urlopen(srv.url("/fw.bin"), timeout=5) as r:
                body = r.read()
            check("normal serves full image",
                  body == b"\x5a" * 1000 and r.headers["Content-Length"] == "1000")

            srv.arm("/t.bin", "truncated")
            try:
                with urllib.request.urlopen(srv.url("/t.bin"), timeout=5) as r:
                    r.read()
            except Exception:
                pass  # incomplete read is the expected outcome
            check("truncated closes mid-stream at 40%",
                  srv.served_bytes == 400 and srv.declared_length == 1000,
                  f"served {srv.served_bytes}/1000 declared")

            try:
                urllib.request.urlopen(srv.url("/nope.bin"), timeout=5)
                ok404 = False
            except urllib.error.HTTPError as e:
                ok404 = e.code == 404
            check("404 for un-armed path", ok404)

            served_before = srv.served_count
            try:
                urllib.request.urlopen(srv.url("/t.bin"), timeout=5)
                oneshot = False
            except urllib.error.HTTPError as e:
                oneshot = e.code == 404
            check("one-shot: consumed arm re-fetch 404s",
                  oneshot and srv.served_count == served_before)

            check("bind guard rejects 0.0.0.0",
                  _bind_refused("0.0.0.0", image))
        finally:
            srv.stop()
        check("clean shutdown (port released)", srv._httpd is None)

        failed = [c for c in checks if not c[1]]
        print(f"selftest: {len(checks) - len(failed)}/{len(checks)} checks OK")
        return 1 if failed else 0


def _bind_refused(host, image):
    try:
        LocalOtaServer(host=host, image_path=image)
        return False
    except ValueError:
        return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true",
                    help="exercise the local OTA server on loopback "
                         "(no device involved)")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
