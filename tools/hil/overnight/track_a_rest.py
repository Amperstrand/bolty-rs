#!/usr/bin/env python3
"""Overnight Track A: REST suite (plan todo 8).

Full REST matrix against the bolty-esp32 REST surface (TLS :81, bearer
scopes, 429 timing, /api/job lifecycle), card-safe by construction:

CARD-SAFETY SHAPE (plan Metis blocker): requests rejected by the auth
middleware (401 paths), malformed JSON (400), unknown routes (404) and
oversized headers NEVER reach the card (rest.rs dispatches only after
is_authorized + body parse) — negatives are confined to those paths plus
NON-card routes (/api/status, /api/uid). No staged wrong keys exist
anywhere in this module: the only keys ever POSTed are the deterministic
k0..k4 derived from the configured HIL_ISSUER via the SAME bolty-cli
bridge the card-safety ledger uses (ledger.py, todo 6).

Card-touching positives (keyver/inspect/ndef/diagnose) run only with
correctly staged deterministic keys, or per the endpoint classification
produced by todo 18's one-call probe (a no-keys /api/keyver on a
provisioned card may itself be a failed card auth since the 51e8a50
keyver fix). Until that file exists every card-touching endpoint
defaults to CARD-AUTH = gated behind staged keys.

Firmware mirror (apps/bolty-esp32/src/rest.rs):
  routes ........ rest.rs:182-285 (13 registrations, ROUTE_TABLE below)
  scopes ........ rest.rs:1171-1218 (TokenScope Read/Write, bearer)
  cooldown ...... rest.rs:34 WRITE_COOLDOWN_US = 5s -> 429 + Retry-After
                  (rest.rs:632-646)
  job slot ...... rest.rs:103-133 (single slot, 201/409, honest result)
  token staging . console `token <v>` sets read AND write token to the
                  SAME value (firmware/console_commands.rs:210-229), so
                  the read-scope-on-write negative is only constructible
                  when a distinct REST_READ_TOKEN is provided.

Suite order is load-bearing: negatives -> job lifecycle (needs NO keys
staged to observe an honest wipe_refused) -> TLS loop -> 429 timing
(STAGES the ledger-derived keys) -> positives -> sanity.

Offline: `python3 track_a_rest.py --selftest` validates the route table
and request builders with no network. Integration: register(ctx) per the
overnight.py PhaseContext lane protocol (duck-typed; standalone mode
falls back to a local card lock).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from ledger import LedgerConfigError, _derive_keys_via_bolty_cli

__all__ = [
    "ROUTE_TABLE",
    "EXPECTED_ROUTE_COUNT",
    "GET_ROUTES",
    "POST_ROUTES",
    "CARD_TOUCHING_ENDPOINTS",
    "UNKNOWN_ROUTE_PATH",
    "DEFAULT_RETRY_AFTER_S",
    "MAX_ATTEMPTS",
    "REQUEST_TIMEOUT_S",
    "Resp",
    "TransportError",
    "RestClient",
    "Pacer",
    "RequestPlan",
    "classify_response",
    "parse_retry_after",
    "load_endpoint_classification",
    "positive_plans",
    "negative_plans",
    "ledger_derived_keys_body",
    "run_429_timing",
    "run_job_lifecycle",
    "run_tls_handshake_loop",
    "register",
    "build_lane",
    "make_ssl_context",
]

# ----------------------------------------------------------- route table ----
# Mirror of the RestServer::start registrations, rest.rs:182-285:
#   status:182  uid:190  check:198  keys:207(POST)  url:216(POST)
#   burn:225(POST)  wipe:234(POST)  keyver:242  ndef:250  diagnose:258
#   inspect:266  job:275(POST)  job:283(GET)
GET_ROUTES = ("status", "uid", "check", "keyver", "ndef", "diagnose", "inspect", "job")
POST_ROUTES = ("keys", "url", "burn", "wipe", "job")
EXPECTED_ROUTE_COUNT = 13
ROUTE_TABLE = frozenset(
    [("GET", f"/api/{n}") for n in GET_ROUTES]
    + [("POST", f"/api/{n}") for n in POST_ROUTES]
)

# GET endpoints whose handler authenticates against the card once keys are
# staged (post-51e8a50 keyver semantics); gated as CARD-AUTH by default.
CARD_TOUCHING_ENDPOINTS = ("keyver", "ndef", "diagnose", "inspect")
ENDPOINT_CLASSIFICATION_FILENAME = "endpoint_classification.json"

UNKNOWN_ROUTE_PATH = "/api/bolty-nonexistent-probe"
HEADER_PROBE_NAME = "X-Bolty-Probe"
HEADER_PROBE_BYTES = 8 * 1024
WRONG_TOKEN_SENTINEL = "wrong-token-by-construction"

REQUEST_TIMEOUT_S = 10.0
MAX_ATTEMPTS = 2  # 1 try + 1 retry — QA bound "no retry storm (<=2 attempts)"
RETRY_BACKOFF_S = 1.0
MIN_REQUEST_INTERVAL_S = 0.2  # <=5 req/s sustained cap
READ_PACE_S = 1.0  # suite-level pacing: >=1s between reads (plan todo 8)
WRITE_COOLDOWN_S = 5.0  # mirrors rest.rs WRITE_COOLDOWN_US
DEFAULT_RETRY_AFTER_S = 5.0
TLS_LOOP_N = 20
JOB_POLL_TIMEOUT_S = 60.0
JOB_POLL_INTERVAL_S = 1.0

DEFAULT_LNURL = "https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c={mac}"

_ISSUER_RE = re.compile(r"[0-9a-f]{32}")
_UID_RE = re.compile(r"[0-9A-F]{14}")
_KEY_RE = re.compile(r"[0-9a-f]{32}")

EXPECT_ALLOWED = {
    "ok": (200,),
    "created": (201,),
    "unauthorized": (401,),
    "unauthorized_or_forbidden": (401, 403),
    "bad_request": (400,),
    "not_found": (404,),
    "rate_limited": (429,),
    # oversized-header bound: any bounded answer, never a 5xx/crash
    "bounded": (200, 201, 400, 401, 403, 404, 413, 429, 431),
}


# ------------------------------------------------------------- clocks ----


class _SystemClock:
    def monotonic(self):
        return time.monotonic()

    def sleep(self, s):
        if s > 0:
            time.sleep(s)


class FakeClock:
    """Deterministic clock for offline tests and --selftest."""

    def __init__(self, t0=0.0):
        self.t = float(t0)

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, float(s))


# -------------------------------------------------------- http plumbing ----


@dataclass
class Resp:
    status: int
    headers: dict
    body: str
    attempts: int = 1

    def header(self, name):
        return self.headers.get(name.lower())


class TransportError(Exception):
    """TLS/transport failure (unreachable, reset, timeout). Never a card
    verdict — the device was not reached, so the ledger never counts it."""

    def __init__(self, detail, attempts=0):
        super().__init__(detail)
        self.attempts = attempts


def make_ssl_context():
    """TLS :81 serves the self-signed provision-cert (AGENTS.md) — verify
    is deliberately off, exactly like the curl -k verify pattern."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def urllib_transport(method, url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=make_ssl_context()
        ) as r:
            return Resp(
                r.status,
                {k.lower(): v for k, v in r.headers.items()},
                r.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read()
        except OSError:
            pass
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        return Resp(e.code, hdrs, raw.decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise TransportError(f"{method} {url}: {e!r}") from e


class Pacer:
    """<=5 req/s sustained cap + client-side 5s write cooldown (mirrors the
    server's WRITE_COOLDOWN_US so the suite never trips 429 by accident).
    The deliberate 429-timing probe bypasses ONLY the write cooldown via
    bypass_write_cooldown=True."""

    def __init__(
        self,
        clock,
        min_interval_s=MIN_REQUEST_INTERVAL_S,
        write_cooldown_s=WRITE_COOLDOWN_S,
    ):
        self.clock = clock
        self.min_interval_s = float(min_interval_s)
        self.write_cooldown_s = float(write_cooldown_s)
        self._next_ok = None
        self._write_ok_at = None

    def wait_before(self, method, bypass_write_cooldown=False):
        now = self.clock.monotonic()
        wait = 0.0
        if self._next_ok is not None:
            wait = max(wait, self._next_ok - now)
        if (
            method == "POST"
            and self._write_ok_at is not None
            and not bypass_write_cooldown
        ):
            wait = max(wait, self._write_ok_at - now)
        return max(0.0, wait)

    def record_sent(self, method):
        self._next_ok = self.clock.monotonic() + self.min_interval_s

    def record_write(self, accepted):
        """Only an ACCEPTED (2xx) write starts a fresh server cooldown; a
        429 rejection leaves the previous cooldown untouched."""
        if accepted:
            self._write_ok_at = self.clock.monotonic() + self.write_cooldown_s


class RestClient:
    """Paced, bounded-retry HTTPS client for the :81 REST surface.

    transport signature: (method, url, headers, body_bytes, timeout) -> Resp
    (injectable so tests run fully offline). auth: "write"|"read"|"wrong"|None.
    """

    def __init__(
        self,
        ip,
        token=None,
        read_token=None,
        port=81,
        timeout_s=REQUEST_TIMEOUT_S,
        transport=None,
        clock=None,
        max_attempts=MAX_ATTEMPTS,
        retry_backoff_s=RETRY_BACKOFF_S,
        pace_s=MIN_REQUEST_INTERVAL_S,
    ):
        self.ip = ip
        self.token = token
        self.read_token = read_token
        self.base_url = f"https://{ip}:{port}"
        self.timeout_s = float(timeout_s)
        self.clock = clock or _SystemClock()
        self.transport = transport or urllib_transport
        self.max_attempts = int(max_attempts)
        self.retry_backoff_s = float(retry_backoff_s)
        self.pacer = Pacer(self.clock, min_interval_s=pace_s)

    def _token_for(self, auth):
        if auth == "write":
            return self.token
        if auth == "read":
            return self.read_token or self.token
        if auth == "wrong":
            return WRONG_TOKEN_SENTINEL
        return None

    def request(
        self,
        method,
        path,
        *,
        body=None,
        headers=None,
        auth: str | None = "write",
        bypass_write_cooldown=False,
    ):
        wait = self.pacer.wait_before(
            method, bypass_write_cooldown=bypass_write_cooldown
        )
        if wait > 0:
            self.clock.sleep(wait)
        hdrs = dict(headers or {})
        token = self._token_for(auth)
        if token is not None:
            hdrs["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            hdrs["Content-Type"] = "application/json"
            data = body.encode("utf-8") if isinstance(body, str) else body
        attempts = 0
        while True:
            attempts += 1
            try:
                resp = self.transport(
                    method, self.base_url + path, hdrs, data, self.timeout_s
                )
            except TransportError as e:
                if attempts >= self.max_attempts:
                    raise TransportError(str(e), attempts=attempts) from e
                self.clock.sleep(self.retry_backoff_s)
                continue
            self.pacer.record_sent(method)
            if method == "POST" and 200 <= resp.status < 300:
                self.pacer.record_write(accepted=True)
            if resp.status >= 500 and attempts < self.max_attempts:
                self.clock.sleep(self.retry_backoff_s)
                continue
            resp.attempts = attempts
            return resp

    def read_token_distinct(self):
        return bool(self.read_token and self.token and self.read_token != self.token)


# ------------------------------------------------- response classification ----


def classify_response(expect, status):
    allowed = EXPECT_ALLOWED[expect]
    return "PASS" if status in allowed else "FAIL"


def parse_retry_after(headers, default=DEFAULT_RETRY_AFTER_S, lo=1.0, hi=60.0):
    raw = None
    for key, value in headers.items():
        if key.lower() == "retry-after":
            raw = value
            break
    if raw is None:
        return default
    try:
        secs = float(raw)
    except (TypeError, ValueError):
        return default
    return min(hi, max(lo, secs))


# ------------------------------------------------ endpoint classification ----


def load_endpoint_classification(path):
    """CARD-AUTH vs FREE per card-touching endpoint. todo 18's one-call
    probe writes {"endpoints": {"keyver": "FREE", ...}} into the results
    dir; a missing OR corrupt file fails SAFE (everything stays gated)."""
    classes = {name: "CARD-AUTH" for name in CARD_TOUCHING_ENDPOINTS}
    classes.update(
        {
            name: "FREE"
            for name in GET_ROUTES + POST_ROUTES
            if name not in CARD_TOUCHING_ENDPOINTS
        }
    )
    if path is None:
        return classes
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        overrides = data["endpoints"]
    except (OSError, ValueError, KeyError, TypeError):
        return classes
    for name in CARD_TOUCHING_ENDPOINTS:
        value = overrides.get(name)
        if value in ("FREE", "CARD-AUTH"):
            classes[name] = value
    return classes


# ------------------------------------------------------------ key staging ----


def ledger_derived_keys_body(issuer_key, uid, version=1, binary="bolty-cli"):
    """The ONLY keys body this suite ever POSTs: k0..k4 straight from the
    ledger's bolty-cli derive-keys bridge (pure computation, no card, no
    embedded literals). Refuses anything the bridge did not produce."""
    issuer = (issuer_key or "").strip().lower()
    if not _ISSUER_RE.fullmatch(issuer):
        raise LedgerConfigError(
            "staged keys require a configured 32-hex issuer key "
            "(HIL_ISSUER) — no fallback key exists"
        )
    uid = (uid or "").strip().upper()
    if not _UID_RE.fullmatch(uid):
        raise LedgerConfigError(f"card uid {uid!r} is not a 14-hex (7-byte) uid")
    keys = _derive_keys_via_bolty_cli(issuer, uid, version, binary)
    parts = []
    for name in ("k0", "k1", "k2", "k3", "k4"):
        value = str(keys.get(name, "")).strip().lower()
        if not _KEY_RE.fullmatch(value):
            raise LedgerConfigError(
                f"derive-keys bridge returned no usable {name} for {uid}"
            )
        parts.append(f'"{name}": "{value}"')
    return "{" + ", ".join(parts) + "}"


# ------------------------------------------------------------ plan model ----


@dataclass(frozen=True)
class RequestPlan:
    name: str
    method: str
    path: str
    body: str | None = None
    headers: dict | None = None
    auth: str | None = "write"  # "write" | "read" | "wrong" | None
    expect: str = "ok"
    skip_reason: str | None = None
    note: str = ""
    bypass_write_cooldown: bool = False


def positive_plans(keys_staged, endpoint_classes=None, lnurl=None):
    """All 13 routes as executable/skip plans. keys_staged=False gates every
    card-touching endpoint (default CARD-AUTH classification) AND burn/wipe
    (a burn/wipe without correct staged keys is exactly the wrong-key auth
    this harness must never attempt)."""
    if endpoint_classes is None:
        endpoint_classes = load_endpoint_classification(None)
    plans = [
        RequestPlan("status", "GET", "/api/status", auth="read", note="non-card"),
        RequestPlan("uid", "GET", "/api/uid", auth="read", note="non-card"),
        RequestPlan("check", "GET", "/api/check", auth="read"),
        RequestPlan("job", "GET", "/api/job", auth="read", note="slot state"),
    ]
    reason = (
        "CARD-AUTH endpoint without staged ledger-derived keys "
        "(gated until todo-18 classification + staging)"
    )
    for name in ("keyver", "ndef", "diagnose", "inspect"):
        skip = None if keys_staged else reason
        plans.append(
            RequestPlan(name, "GET", f"/api/{name}", auth="read", skip_reason=skip)
        )
    if keys_staged:
        plans.append(
            RequestPlan(
                "keys", "POST", "/api/keys", body="{{KEYS_BODY}}", note="ledger-derived"
            )
        )
    else:
        plans.append(RequestPlan("keys", "POST", "/api/keys", skip_reason=reason))
    url_body = json.dumps({"url": lnurl or os.environ.get("HIL_URL") or DEFAULT_LNURL})
    plans.append(RequestPlan("url", "POST", "/api/url", body=url_body))
    for name in ("burn", "wipe"):
        plans.append(
            RequestPlan(
                name,
                "POST",
                f"/api/{name}",
                skip_reason=None if keys_staged else reason,
            )
        )
    # 12 executable/skip plans; the 13th route (POST /api/job) is exercised
    # by run_job_lifecycle — the matrix must account for every route
    covered = {p.name for p in plans}
    assert covered == set(GET_ROUTES) | {"keys", "url", "burn", "wipe"}
    return plans


def negative_plans(read_token_distinct):
    """Middleware-rejected negatives ONLY (they never reach the card) plus
    non-card-route sanity probes. No staged wrong keys by construction."""
    plans = [
        RequestPlan(
            "no_token_status", "GET", "/api/status", auth=None, expect="unauthorized"
        ),
        RequestPlan(
            "wrong_token_status",
            "GET",
            "/api/status",
            auth="wrong",
            expect="unauthorized",
        ),
    ]
    if read_token_distinct:
        plans.append(
            RequestPlan(
                "read_scope_on_write",
                "POST",
                "/api/keys",
                auth="read",
                expect="unauthorized_or_forbidden",
            )
        )
    else:
        plans.append(
            RequestPlan(
                "read_scope_on_write",
                "POST",
                "/api/keys",
                auth="read",
                expect="unauthorized_or_forbidden",
                skip_reason="read and write tokens are identical (console `token` "
                "sets both, console_commands.rs:210-229) — negative "
                "not constructible without a distinct REST_READ_TOKEN",
            )
        )
    plans += [
        # unterminated string value: extract_json_string (rest.rs:1111) finds
        # no closing quote -> 400 BEFORE any dispatch — never a real write
        RequestPlan(
            "malformed_json_url",
            "POST",
            "/api/url",
            auth="write",
            body='{"url": "no-closing-quote',
            expect="bad_request",
        ),
        RequestPlan(
            "unknown_route", "GET", UNKNOWN_ROUTE_PATH, auth=None, expect="not_found"
        ),
        RequestPlan(
            "header_8kb",
            "GET",
            "/api/status",
            auth=None,
            headers={HEADER_PROBE_NAME: "A" * HEADER_PROBE_BYTES},
            expect="bounded",
        ),
        RequestPlan(
            "alive_after_header",
            "GET",
            "/api/status",
            auth="read",
            expect="ok",
            note="8KB did not crash the server",
        ),
        RequestPlan(
            "sanity_uid",
            "GET",
            "/api/uid",
            auth="read",
            expect="ok",
            note="non-card sanity",
        ),
    ]
    return plans


# ------------------------------------------------------------ live flows ----


def run_429_timing(client, ctx, keys_body, sleep_fn):
    """Two rapid POST /api/keys with CORRECT ledger-derived keys -> 2nd is
    429 + Retry-After ~5s (rest.rs:632-646), then success after sleeping
    the header out. The first accepted POST is also this suite's staging
    action, so the row type doubles as the stage_keys record."""
    rows = []
    with ctx.card("stick"):
        first = client.request("POST", "/api/keys", body=keys_body)
        rows.append(
            {
                "type": "stage_keys",
                "case": "timing_429_stage",
                "expect": "ok",
                "status": classify_response("ok", first.status),
                "code": first.status,
                "attempts": first.attempts,
            }
        )
        second = client.request(
            "POST", "/api/keys", body=keys_body, bypass_write_cooldown=True
        )
        retry_after = parse_retry_after(second.headers)
        rows.append(
            {
                "type": "timing_429",
                "case": "timing_429_second",
                "expect": "rate_limited",
                "status": classify_response("rate_limited", second.status),
                "code": second.status,
                "attempts": second.attempts,
                "retry_after_s": retry_after,
            }
        )
        sleep_fn(max(retry_after + 1.0, 6.0))
        third = client.request("POST", "/api/keys", body=keys_body)
        rows.append(
            {
                "type": "timing_429",
                "case": "timing_429_after_sleep",
                "expect": "ok",
                "status": classify_response("ok", third.status),
                "code": third.status,
                "attempts": third.attempts,
                "slept_s": round(max(retry_after + 1.0, 6.0), 1),
            }
        )
    return rows


def run_job_lifecycle(
    client,
    ctx,
    sleep_fn,
    poll_timeout_s=JOB_POLL_TIMEOUT_S,
    poll_interval_s=JOB_POLL_INTERVAL_S,
):
    """POST /api/job wipe with NO keys staged -> poll GET /api/job to
    completed; expect an honest wipe_refused-class result. Any other
    result is recorded honestly as FAIL (e.g. keys staged by a sibling
    track made the wipe real)."""
    with ctx.card("stick"):
        try:
            submit = client.request("POST", "/api/job", body='{"command":"wipe"}')
        except TransportError as e:
            return {
                "status": "FAIL",
                "result": None,
                "reason": repr(e),
                "polls": 0,
                "submit_code": None,
            }
        if submit.status != 201:
            return {
                "status": classify_response("created", submit.status),
                "result": None,
                "reason": f"submit code {submit.status}",
                "polls": 0,
                "submit_code": submit.status,
            }
        deadline = client.clock.monotonic() + poll_timeout_s
        polls = 0
        status = result = None
        while client.clock.monotonic() < deadline:
            sleep_fn(poll_interval_s)
            polls += 1
            try:
                poll = client.request("GET", "/api/job", auth="read")
            except TransportError:
                continue
            try:
                payload = json.loads(poll.body)
            except ValueError:
                continue
            status = payload.get("status")
            result = payload.get("result")
            if status == "completed":
                break
        ok = status == "completed" and result == "wipe_refused"
        return {
            "status": "PASS" if ok else "FAIL",
            "result": result,
            "reason": None
            if ok
            else f"job status={status!r} "
            f"(expected completed/wipe_refused — were keys staged?)",
            "polls": polls,
            "submit_code": submit.status,
        }


def run_tls_handshake_loop(client, ctx, n=TLS_LOOP_N, sleep_fn=None):
    """TLS :81 handshake stability: n paced no-auth GETs, each proving the
    self-signed TLS layer + the auth middleware (401 without a token)."""
    ok_401 = 0
    anomalies = []
    for i in range(n):
        try:
            resp = client.request("GET", "/api/status", auth=None)
            if resp.status == 401:
                ok_401 += 1
            else:
                anomalies.append(f"probe {i}: code {resp.status}")
        except TransportError as e:
            anomalies.append(f"probe {i}: {e!r}")
        if sleep_fn is not None and i < n - 1:
            sleep_fn(READ_PACE_S)
    ok = ok_401 == n
    return {
        "type": "tls_loop",
        "status": "PASS" if ok else "FAIL",
        "n": n,
        "ok_401": ok_401,
        "anomalies": anomalies[:5],
    }


# ------------------------------------------------------- suite/register ----


class _LocalCardLock:
    """Standalone fallback when no PhaseContext card mutex is injected."""

    def __init__(self):
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def hold(self, card_id, who="standalone", timeout=None):
        del card_id, who, timeout
        self._lock.acquire()
        try:
            yield "stick"
        finally:
            self._lock.release()


def _classification_path():
    results_root = Path(__file__).resolve().parent / "results"
    candidates = sorted(results_root.glob(f"*/{ENDPOINT_CLASSIFICATION_FILENAME}"))
    return candidates[-1] if candidates else None


def _feed_ledger(ctx, resp, card_uid, op=None):
    ledger_api = getattr(ctx, "ledger", None)
    if ledger_api is None or not card_uid:
        return
    if op is not None and hasattr(ledger_api, "record_op"):
        ledger_api.record_op(card_uid, op)
    if hasattr(ledger_api, "record_classified"):
        ledger_api.record_classified(card_uid, resp.body)


def register(ctx, client=None, clock=None):
    """Run the full REST suite against a PhaseContext lane (overnight.py
    protocol). REST_IP is read lazily from the environment — absent means
    standalone mode (one honest SKIP row, no network attempted)."""
    if client is None:
        ip = (os.environ.get("REST_IP") or "").strip()
        if not ip:
            ctx.skip(
                "REST_IP not set in environment — standalone mode only "
                "(device IP is staged into overnight.env at rehearsal, "
                "todo 18)"
            )
            return
        client = RestClient(
            ip=ip,
            token=os.environ.get("REST_TOKEN") or None,
            read_token=os.environ.get("REST_READ_TOKEN") or None,
            clock=clock or _SystemClock(),
            pace_s=READ_PACE_S,
        )
    clock = client.clock

    def sleeper(s):
        clock.sleep(s)
        if hasattr(ctx, "sleep"):
            ctx.sleep(s)

    card_lock = ctx.card if hasattr(ctx, "card") else _LocalCardLock().hold
    card_uid = (os.environ.get("HIL_UID_STICK") or "").strip().upper() or None
    ctx.row(
        type="suite",
        case="start",
        status="INFO",
        base_url=client.base_url,
        auth="token" if client.token else "none",
        distinct_read_token=client.read_token_distinct(),
    )

    # 1. negatives — middleware-rejected only, never the card
    for plan in negative_plans(client.read_token_distinct()):
        if plan.skip_reason:
            ctx.skip(plan.skip_reason, case=f"negative.{plan.name}")
            continue
        try:
            resp = client.request(
                plan.method,
                plan.path,
                body=plan.body,
                headers=plan.headers,
                auth=plan.auth,
            )
        except TransportError as e:
            if plan.expect == "bounded":
                ctx.row(
                    type="negative",
                    case=plan.name,
                    status="PASS",
                    expect=plan.expect,
                    code=None,
                    detail="connection bounded (dropped) — no 5xx",
                )
            else:
                ctx.anomaly("rest_transport", case=plan.name, error=repr(e))
            continue
        ctx.row(
            type="negative",
            case=plan.name,
            status=classify_response(plan.expect, resp.status),
            expect=plan.expect,
            code=resp.status,
            attempts=resp.attempts,
            note=plan.note,
        )

    # 2. job lifecycle — MUST run before any staging (wipe_refused needs
    #    no keys staged)
    lifecycle = run_job_lifecycle(client, ctx, sleeper)
    ctx.row(type="job_lifecycle", case="wipe_no_keys", **lifecycle)

    # 3. TLS handshake loop
    tls_row = run_tls_handshake_loop(client, ctx, sleep_fn=sleeper)
    ctx.row(**tls_row)

    # 4+5. staging + 429 timing, then positives (order is load-bearing:
    #     the timing probe's first POST IS the staging action)
    issuer = (os.environ.get("HIL_ISSUER") or "").strip().lower()
    keys_body = None
    if not _ISSUER_RE.fullmatch(issuer) or not card_uid:
        ctx.skip(
            "no ledger-derived keys available (HIL_ISSUER/HIL_UID_STICK "
            "unset or bolty-cli bridge unavailable) — 429 timing + "
            "CARD-AUTH endpoints + burn/wipe skipped",
            case="timing_429",
        )
    else:
        try:
            keys_body = ledger_derived_keys_body(issuer, card_uid)
        except (LedgerConfigError, OSError, ValueError) as e:
            ctx.skip(
                f"key derivation unavailable: {e!r} — 429 timing + "
                "CARD-AUTH endpoints skipped",
                case="timing_429",
            )
    if keys_body is not None:
        for row in run_429_timing(client, ctx, keys_body, sleeper):
            ctx.row(**row)

    classes = load_endpoint_classification(_classification_path())
    for plan in positive_plans(
        keys_staged=keys_body is not None, endpoint_classes=classes
    ):
        if plan.skip_reason:
            ctx.skip(plan.skip_reason, case=f"positive.{plan.name}")
            continue
        body = plan.body
        if plan.name == "keys":
            continue  # already staged by the 429-timing probe above
        is_mutation = plan.method == "POST"
        try:
            if is_mutation:
                with card_lock("stick"):
                    resp = client.request(
                        plan.method, plan.path, body=body, auth=plan.auth
                    )
            else:
                resp = client.request(plan.method, plan.path, auth=plan.auth)
        except TransportError as e:
            ctx.anomaly("rest_transport", case=plan.name, error=repr(e))
            continue
        if plan.name in CARD_TOUCHING_ENDPOINTS or plan.name in ("burn", "wipe"):
            _feed_ledger(
                ctx,
                resp,
                card_uid,
                op=plan.name if plan.name in ("burn", "wipe") else None,
            )
        ctx.row(
            type="positive",
            case=plan.name,
            status=classify_response(plan.expect, resp.status),
            expect=plan.expect,
            code=resp.status,
            attempts=resp.attempts,
            body_tail=resp.body.strip()[-120:],
        )

    # 6. sanity close-out
    try:
        final = client.request("GET", "/api/status", auth="read")
        ctx.row(
            type="suite",
            case="end",
            status="INFO",
            code=final.status,
            detail="server alive at suite end",
        )
    except TransportError as e:
        ctx.anomaly("rest_transport", case="end", error=repr(e))


def build_lane():
    """LaneSpec for the overnight orchestrator (window1, stick card).

    Duck-typed fallback for a shadowed import (sibling __init__.py makes
    `import overnight` resolve to the docstring-only package under pytest)
    — mirrors track_c.build_lane.
    """
    spec_cls = None
    try:
        import overnight
        spec_cls = getattr(overnight, "LaneSpec", None)
    except ImportError:
        pass
    if spec_cls is None:
        from types import SimpleNamespace
        return SimpleNamespace(name="track_a_rest",
                               target=lambda ctx: register(ctx),
                               window="window1", cards=("stick",),
                               pace_s=READ_PACE_S)
    return spec_cls("track_a_rest", lambda ctx: register(ctx),
                    window="window1", cards=("stick",), pace_s=READ_PACE_S)


# --------------------------------------------------------------- selftest ----


def _selftest():
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))

    check("route table count == 13", len(ROUTE_TABLE) == EXPECTED_ROUTE_COUNT)
    check(
        "route split 8 GET / 5 POST",
        len([1 for m, _ in ROUTE_TABLE if m == "GET"]) == 8
        and len([1 for m, _ in ROUTE_TABLE if m == "POST"]) == 5,
    )
    check(
        "unknown probe route is not a real route",
        all(p != UNKNOWN_ROUTE_PATH for _, p in ROUTE_TABLE),
    )
    classes = load_endpoint_classification(None)
    check(
        "default classification gates all card-touching GETs",
        all(classes[n] == "CARD-AUTH" for n in CARD_TOUCHING_ENDPOINTS),
    )
    check(
        "retry-after parser: header/missing/garbage/clamp",
        parse_retry_after({"Retry-After": "5"}) == 5
        and parse_retry_after({}) == DEFAULT_RETRY_AFTER_S
        and parse_retry_after({"retry-after": "x"}) == DEFAULT_RETRY_AFTER_S
        and parse_retry_after({"retry-after": "999"}) == 60,
    )
    check(
        "response classifiers 200/201/400/401/403/404/429",
        classify_response("ok", 200) == "PASS"
        and classify_response("created", 201) == "PASS"
        and classify_response("bad_request", 400) == "PASS"
        and classify_response("unauthorized", 401) == "PASS"
        and classify_response("unauthorized_or_forbidden", 403) == "PASS"
        and classify_response("not_found", 404) == "PASS"
        and classify_response("rate_limited", 429) == "PASS"
        and classify_response("bounded", 500) == "FAIL",
    )
    clock = FakeClock()
    pacer = Pacer(clock)
    waits = []
    for _ in range(6):
        w = pacer.wait_before("GET")
        waits.append(w)
        clock.sleep(w)
        pacer.record_sent("GET")
    check(
        "pacer caps sustained rate <=5 req/s",
        clock.t >= 1.0 and all(w >= 0.199 for w in waits[1:]),
    )
    pacer.record_sent("POST")
    pacer.record_write(accepted=True)
    check(
        "pacer enforces 5s write cooldown",
        abs(pacer.wait_before("POST") - WRITE_COOLDOWN_S) < 0.01,
    )
    check(
        "pacer bypass only for the deliberate 429 probe",
        pacer.wait_before("POST", bypass_write_cooldown=True) < 1.0,
    )
    for plan in negative_plans(read_token_distinct=False):
        assert plan.path.startswith("/api/"), plan
    plan8k = next(p for p in negative_plans(False) if p.name == "header_8kb")
    check(
        "8KB header probe is 8192 bytes",
        plan8k.headers is not None
        and len(plan8k.headers[HEADER_PROBE_NAME]) == HEADER_PROBE_BYTES,
    )
    malformed = next(p for p in negative_plans(False) if p.name == "malformed_json_url")
    check(
        "malformed JSON body has no closed url value",
        malformed.body is not None
        and re.search(r'"url"\s*:\s*"[^"]*"', malformed.body) is None,
    )
    gated = positive_plans(keys_staged=False)
    check(
        "positives gate card-touching endpoints without staged keys",
        all(
            p.skip_reason
            for p in gated
            if p.name in CARD_TOUCHING_ENDPOINTS + ("burn", "wipe", "keys")
        ),
    )
    open_plans = positive_plans(keys_staged=True)
    check(
        "positives open all routes with staged keys",
        all(p.skip_reason is None for p in open_plans),
    )
    try:
        ledger_derived_keys_body("not-hex", "04C474FA967380")
        refused = False
    except LedgerConfigError:
        refused = True
    check("staged keys refuse anything but a valid issuer (no fallback)", refused)
    check(
        "TLS context is unverified (self-signed provision-cert)",
        make_ssl_context().verify_mode.name == "CERT_NONE",
    )

    failed = [n for n, ok in checks if not ok]
    print(f"selftest: {len(checks) - len(failed)}/{len(checks)} checks passed")
    print(
        f"selftest: route table = {len(ROUTE_TABLE)} routes "
        f"({len(GET_ROUTES)} GET / {len(POST_ROUTES)} POST) mirroring "
        f"rest.rs:182-285"
    )
    for name in failed:
        print(f"selftest: FAILED — {name}", file=sys.stderr)
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Overnight Track A REST suite (plan todo 8)"
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="offline validation: route table + request builders (no network)",
    )
    args = ap.parse_args(argv)
    if args.selftest:
        return _selftest()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
