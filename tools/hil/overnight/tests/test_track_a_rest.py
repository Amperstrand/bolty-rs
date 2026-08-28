#!/usr/bin/env python3
"""Tests for overnight Track A: REST suite (plan todo 8).

Pure-logic TDD suite: the 13-route table (asserted BOTH as constants and
against the live rest.rs registrations), CARD-AUTH endpoint gating, the
429/Retry-After parser, the pacing enforcer (<=5 req/s, 5s write cooldown),
middleware-only negatives (never staged keys, never card routes), response
classifiers, retry-storm bounds, the register(ctx) integration against a
duck-typed fake PhaseContext, and the offline --selftest. No network: the
HTTP layer is a scripted transport.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/overnight/tests/test_track_a_rest.py -q
"""

import contextlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import track_a_rest as tar  # noqa: E402
from track_a_rest import (  # noqa: E402
    CARD_TOUCHING_ENDPOINTS,
    MAX_ATTEMPTS,
    Resp,
    classify_response,
    ledger_derived_keys_body,
    load_endpoint_classification,
    parse_retry_after,
)

REST_RS = (
    Path(__file__).resolve().parents[4] / "apps" / "bolty-esp32" / "src" / "rest.rs"
)

UID_STICK = "04C474FA967380"


# ---------------------------------------------------------------- fakes ----


class FakeClock:
    def __init__(self, t0=0.0):
        self.t = float(t0)

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, float(s))


class FakeTransport:
    """Scripted HTTP transport. `script` items are Resp tuples or Resp;
    when exhausted (or if None) `handler(method, path, headers, body)` decides.
    Every call is recorded as (method, path, headers, body)."""

    def __init__(self, script=None, handler=None):
        self.script = [
            Resp(*item) if not isinstance(item, Resp) else item
            for item in (script or [])
        ]
        self.handler = handler
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        path = url.split(":81", 1)[-1]
        self.calls.append((method, path, dict(headers), body))
        if self.script:
            return self.script.pop(0)
        if self.handler is not None:
            return self.handler(method, path, headers, body)
        raise AssertionError(f"unexpected request {method} {path}")


class FakeCardLock:
    """Duck-typed stand-in for overnight.CardMutex/ctx.card protocol."""

    def __init__(self):
        self.depth = 0
        self.acquisitions = []

    @contextlib.contextmanager
    def hold(self, card_id):
        self.acquisitions.append(card_id)
        self.depth += 1
        try:
            yield card_id
        finally:
            self.depth -= 1


class FakeCtx:
    """Duck-typed PhaseContext (overnight.py lane API)."""

    def __init__(self, lock=None):
        self.name = "track_a_rest"
        self.rows = []
        self.events = []
        self.sleep_log = []
        self.lock = lock or FakeCardLock()
        self.ledger: object = None

    def running(self):
        return True

    def paused(self):
        return False

    def sleep(self, s):
        self.sleep_log.append(s)

    def card(self, card_id):
        return self.lock.hold(card_id)

    def row(self, **fields):
        self.rows.append(fields)
        return fields

    def skip(self, reason, **fields):
        return self.row(type="SKIP", status="SKIP", reason=reason, **fields)

    def anomaly(self, kind, **fields):
        return self.row(type="anomaly", status="ANOMALY", kind=kind, **fields)

    def event(self, kind, **fields):
        self.events.append((kind, fields))
        return fields


def fake_ledger():
    fed = []

    def record_classified(card, text):
        fed.append(("classified", card, text))
        return "unknown"

    def record_op(card, op):
        fed.append(("op", card, op))

    def record_transport_event(card, text=""):
        fed.append(("transport", card, text))

    return SimpleNamespace(
        record_classified=record_classified,
        record_op=record_op,
        record_transport_event=record_transport_event,
    ), fed


def fake_derive_bridge(keys=None, fail=False):
    def bridge(issuer, uid, version, binary="bolty-cli"):
        if fail:
            raise tar.LedgerConfigError("no bolty-cli")
        return dict(
            keys
            or {
                "ok": True,
                "version": version,
                "k0": "aa" * 16,
                "k1": "bb" * 16,
                "k2": "cc" * 16,
                "k3": "dd" * 16,
                "k4": "ee" * 16,
            }
        )

    return bridge


# --------------------------------------------------------- route table ----


def test_route_table_is_exactly_13_routes():
    assert len(tar.ROUTE_TABLE) == 13
    assert len(tar.ROUTE_TABLE) == tar.EXPECTED_ROUTE_COUNT


def test_route_table_get_post_split():
    gets = sorted(p for m, p in tar.ROUTE_TABLE if m == "GET")
    posts = sorted(p for m, p in tar.ROUTE_TABLE if m == "POST")
    assert gets == sorted(f"/api/{n}" for n in tar.GET_ROUTES)
    assert posts == sorted(f"/api/{n}" for n in tar.POST_ROUTES)
    assert len(gets) == 8 and len(posts) == 5


def test_route_table_matches_rest_rs_registrations():
    """Fails when rest.rs adds/removes a route: the harness table must mirror
    the firmware registrations byte-for-byte (documented rest.rs:182-285)."""
    if not REST_RS.exists():
        pytest.skip(f"rest.rs not found at {REST_RS}")
    src = REST_RS.read_text(encoding="utf-8")
    registered = {
        (method.upper(), path)
        for path, method in re.findall(
            r'fn_handler\("(/api/\w+)",\s*Method::(\w+)', src
        )
    }
    assert registered == set(tar.ROUTE_TABLE), (
        f"rest.rs registrations {sorted(registered)} != harness table "
        f"{sorted(tar.ROUTE_TABLE)} — update ROUTE_TABLE + rest.rs line refs"
    )


# ----------------------------------------------- endpoint classification ----


def test_endpoint_classification_defaults_gate_card_touching():
    cls = load_endpoint_classification(None)
    for name in CARD_TOUCHING_ENDPOINTS:
        assert cls[name] == "CARD-AUTH", name
    for name in ("status", "uid", "check", "job", "keys", "url"):
        assert cls[name] == "FREE", name


def test_endpoint_classification_file_overrides(tmp_path):
    f = tmp_path / "endpoint_classification.json"
    f.write_text(json.dumps({"endpoints": {"keyver": "FREE", "inspect": "FREE"}}))
    cls = load_endpoint_classification(f)
    assert cls["keyver"] == "FREE"
    assert cls["inspect"] == "FREE"
    assert cls["ndef"] == "CARD-AUTH"  # untouched endpoints stay gated


def test_endpoint_classification_corrupt_file_fails_safe_gated(tmp_path):
    f = tmp_path / "endpoint_classification.json"
    f.write_text("{ not json")
    cls = load_endpoint_classification(f)
    for name in CARD_TOUCHING_ENDPOINTS:
        assert cls[name] == "CARD-AUTH"  # fail-safe: gated


# ------------------------------------------------------------ matrices ----


def test_positive_matrix_gates_card_auth_endpoints_without_staged_keys():
    plans = tar.positive_plans(keys_staged=False)
    by_name = {p.name: p for p in plans}
    for name in CARD_TOUCHING_ENDPOINTS:
        p = by_name[name]
        assert p.skip_reason, f"{name} must carry a skip reason when gated"
        assert "CARD-AUTH" in p.skip_reason
    # every non-card route is an executable plan
    for name in ("status", "uid", "check", "job"):
        assert by_name[name].skip_reason is None


def test_positive_matrix_calls_gated_endpoints_when_keys_staged():
    plans = tar.positive_plans(keys_staged=True)
    gated = [p for p in plans if p.name in CARD_TOUCHING_ENDPOINTS]
    assert gated and all(p.skip_reason is None for p in gated)
    burn = next(p for p in plans if p.name == "burn")
    wipe = next(p for p in plans if p.name == "wipe")
    assert burn.skip_reason is None and wipe.skip_reason is None


def test_negative_matrix_never_touches_card_routes_or_stages_keys():
    plans = tar.negative_plans(read_token_distinct=False)
    card_routes = {
        f"/api/{n}" for n in ("keyver", "ndef", "diagnose", "inspect", "burn", "wipe")
    }
    for p in plans:
        assert p.path not in card_routes, f"negative touches card route {p.path}"
        if p.method == "POST" and p.auth == "write":
            # the ONLY write-authed negative body must be unparsable middleware
            # fodder — never a stageable keys/url body (no closed JSON string)
            assert "k0" not in (p.body or ""), p.name
            assert not re.search(r'"url"\s*:\s*"[^"]*"', p.body or ""), p.name
        assert p.path.startswith("/api/")
    plan8k = next(p for p in plans if p.name == "header_8kb")
    assert plan8k.headers is not None
    assert len(plan8k.headers["X-Bolty-Probe"]) >= 8 * 1024


def test_negative_matrix_read_scope_negative_conditional_on_distinct_tokens():
    distinct = {p.name: p for p in tar.negative_plans(read_token_distinct=True)}
    same = {p.name: p for p in tar.negative_plans(read_token_distinct=False)}
    assert distinct["read_scope_on_write"].skip_reason is None
    assert same["read_scope_on_write"].skip_reason
    assert "identical" in same["read_scope_on_write"].skip_reason


def test_unknown_route_is_not_a_real_route():
    assert tar.UNKNOWN_ROUTE_PATH not in {p for _, p in tar.ROUTE_TABLE}


# ------------------------------------------------- 429 + classifiers ----


def test_parse_retry_after_variants():
    assert parse_retry_after({"retry-after": "5"}) == 5
    assert parse_retry_after({"Retry-After": "3"}) == 3
    assert parse_retry_after({}) == tar.DEFAULT_RETRY_AFTER_S  # missing -> default
    assert parse_retry_after({"retry-after": "garbage"}) == tar.DEFAULT_RETRY_AFTER_S
    assert parse_retry_after({"retry-after": "999"}) == 60  # clamped sane


def test_classify_response_matrix():
    assert classify_response("ok", 200) == "PASS"
    assert classify_response("ok", 500) == "FAIL"
    assert classify_response("created", 201) == "PASS"
    assert classify_response("unauthorized", 401) == "PASS"
    assert classify_response("unauthorized", 200) == "FAIL"
    assert classify_response("unauthorized_or_forbidden", 401) == "PASS"
    assert classify_response("unauthorized_or_forbidden", 403) == "PASS"
    assert classify_response("bad_request", 400) == "PASS"
    assert classify_response("bad_request", 413) == "FAIL"
    assert classify_response("not_found", 404) == "PASS"
    assert classify_response("rate_limited", 429) == "PASS"
    assert classify_response("rate_limited", 200) == "FAIL"
    assert classify_response("bounded", 431) == "PASS"
    assert classify_response("bounded", 500) == "FAIL"


# ------------------------------------------------------------- pacing ----


def test_pacer_enforces_request_cap_and_write_cooldown():
    clock = FakeClock()
    pacer = tar.Pacer(clock, min_interval_s=0.2, write_cooldown_s=5.0)
    # <=5 req/s sustained cap: 6 requests need >= 5 * 0.2s of spacing
    waits = []
    for _ in range(6):
        w = pacer.wait_before("GET")
        waits.append(w)
        clock.sleep(w)
        pacer.record_sent("GET")
    assert all(w >= 0.199 for w in waits[1:])
    assert clock.t >= 1.0
    # write cooldown: an accepted write blocks the next write ~5s
    pacer.record_sent("POST")
    pacer.record_write(accepted=True)
    w = pacer.wait_before("POST")
    assert w == pytest.approx(5.0, abs=0.01)


def test_pacer_bypass_for_deliberate_429():
    clock = FakeClock()
    pacer = tar.Pacer(clock, min_interval_s=0.2, write_cooldown_s=5.0)
    pacer.record_sent("POST")
    pacer.record_write(accepted=True)
    w = pacer.wait_before("POST", bypass_write_cooldown=True)
    assert w < 1.0  # only the min-interval cap remains


# --------------------------------------------------------- rest client ----


def make_client(script=None, handler=None, clock=None):
    clock = clock or FakeClock()
    transport = FakeTransport(script=script, handler=handler)
    return (
        tar.RestClient(
            ip="192.0.2.10", token="test-token", clock=clock, transport=transport
        ),
        transport,
        clock,
    )


def test_client_request_build_headers_and_ssl():
    client, transport, _ = make_client(script=[(200, {}, '{"ok":true}')])
    resp = client.request("GET", "/api/status")
    method, path, headers, body = transport.calls[-1]
    assert method == "GET" and path == "/api/status"
    assert headers["Authorization"] == "Bearer test-token"
    assert client.base_url == "https://192.0.2.10:81"
    assert resp.status == 200
    # TLS is deliberately unverified (self-signed provision-cert, AGENTS.md)
    ctx = tar.make_ssl_context()
    assert ctx.check_hostname is False and ctx.verify_mode.name == "CERT_NONE"


def test_client_no_auth_variant():
    client, transport, _ = make_client(script=[(401, {}, '{"ok":false}')])
    client.request("GET", "/api/status", auth=None)
    assert "Authorization" not in transport.calls[-1][2]


def test_client_no_retry_storm_on_5xx():
    # QA contract: injected 5xx -> bounded attempts (<= MAX_ATTEMPTS == 2), no storm
    boom = lambda *a: Resp(500, {}, '{"ok":false}')  # noqa: E731
    client, transport, clock = make_client(handler=boom)
    resp = client.request("GET", "/api/status")
    assert resp.status == 500
    assert resp.attempts == MAX_ATTEMPTS == 2
    assert len(transport.calls) == 2


def test_client_retries_once_on_transport_error_then_succeeds():
    state = {"n": 0}

    def flaky(method, path, headers, body):
        state["n"] += 1
        if state["n"] == 1:
            raise tar.TransportError("conn reset")
        return Resp(200, {}, '{"ok":true}')

    client, transport, clock = make_client(handler=flaky)
    resp = client.request("GET", "/api/status")
    assert resp.status == 200 and resp.attempts == 2


def test_client_gives_up_after_max_attempts_on_transport_error():
    def dead(*a):
        raise tar.TransportError("timeout")

    client, transport, clock = make_client(handler=dead)
    with pytest.raises(tar.TransportError):
        client.request("GET", "/api/status")
    assert len(transport.calls) == MAX_ATTEMPTS


def test_client_records_write_cooldown_only_on_accepted_write():
    client, transport, clock = make_client(
        script=[(200, {}, "{}"), (429, {"retry-after": "5"}, "{}")]
    )
    client.request("POST", "/api/url", body='{"url":"https://x/"}')
    t_after_write = clock.t
    client.request(
        "POST", "/api/url", body='{"url":"https://y/"}', bypass_write_cooldown=True
    )
    # the 429 write did NOT extend the cooldown: waiting from the FIRST write
    w = client.pacer.wait_before("POST")
    assert w == pytest.approx(5.0 - (clock.t - t_after_write), abs=0.05)


# ------------------------------------------------------ staged keys ----


def test_ledger_derived_keys_body_from_bridge_only(monkeypatch):
    monkeypatch.setattr(tar, "_derive_keys_via_bolty_cli", fake_derive_bridge())
    body = json.loads(ledger_derived_keys_body("11" * 16, UID_STICK))
    assert set(body) == {"k0", "k1", "k2", "k3", "k4"}
    assert body["k0"] == "aa" * 16
    # the bridge receives EXACTLY the configured issuer/uid — no fallbacks
    seen = []
    monkeypatch.setattr(
        tar,
        "_derive_keys_via_bolty_cli",
        lambda iss, uid, ver, binary="bolty-cli": (
            seen.append((iss, uid, ver)),
            fake_derive_bridge()(iss, uid, ver, binary),
        )[1],
    )
    ledger_derived_keys_body("22" * 16, UID_STICK, version=1)
    assert seen == [("22" * 16, UID_STICK, 1)]


def test_ledger_derived_keys_body_rejects_incomplete_bridge_output(monkeypatch):
    broken = dict.fromkeys(("k0", "k1", "k2", "k3"), "aa" * 16)  # k4 missing
    monkeypatch.setattr(
        tar, "_derive_keys_via_bolty_cli", fake_derive_bridge(keys=broken)
    )
    with pytest.raises(tar.LedgerConfigError):
        ledger_derived_keys_body("11" * 16, UID_STICK)


def test_static_audit_no_key_literals_in_module():
    src = Path(tar.__file__).read_text(encoding="utf-8")
    hits = re.findall(r"\b[0-9a-fA-F]{32}\b", src)
    assert not hits, f"32-hex key-like literals in module source: {hits}"


# ------------------------------------------------------- live flows ----


def test_429_timing_flow_three_posts_and_sleep():
    script = [
        Resp(200, {}, '{"ok":true}'),
        Resp(429, {"retry-after": "5"}, '{"ok":false,"error":"rate limited"}'),
        Resp(200, {}, '{"ok":true}'),
    ]
    client, transport, clock = make_client(script=script)
    ctx = FakeCtx()
    rows = tar.run_429_timing(
        client, ctx, keys_body='{"k0":"aa"}', sleep_fn=clock.sleep
    )
    posts = [c for c in transport.calls if c[0] == "POST" and c[1] == "/api/keys"]
    assert len(posts) == 3
    assert all(b'"k0":"aa"' in (c[3] or b"") for c in posts)
    # slept >= Retry-After + 1 (spec: success after sleep 6 with r=5)
    assert clock.t >= 6.0
    assert all(r["status"] == "PASS" for r in rows)
    retry_row = next(r for r in rows if r.get("expect") == "rate_limited")
    assert retry_row["retry_after_s"] == 5


def test_job_lifecycle_poll_to_completed_wipe_refused():
    clock = FakeClock()
    script = [
        Resp(201, {}, '{"ok":true,"job_id":1,"status":"pending"}'),
        Resp(200, {}, '{"ok":true,"job_id":1,"status":"running","result":null}'),
        Resp(
            200,
            {},
            '{"ok":true,"job_id":1,"status":"completed",'
            '"command":"wipe","result":"wipe_refused"}',
        ),
    ]
    client, transport, _ = make_client(script=script, clock=clock)
    ctx = FakeCtx()
    row = tar.run_job_lifecycle(client, ctx, sleep_fn=clock.sleep)
    assert row["status"] == "PASS"
    assert row["result"] == "wipe_refused"
    posts = [c for c in transport.calls if c[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "/api/job"
    assert b"wipe" in (posts[0][3] or b"")
    assert ctx.lock.acquisitions == ["stick"]  # mutation ran under the mutex


def test_job_lifecycle_honest_fail_on_unexpected_result():
    script = [
        Resp(201, {}, '{"ok":true,"job_id":1,"status":"pending"}'),
        Resp(
            200,
            {},
            '{"ok":true,"job_id":1,"status":"completed",'
            '"command":"wipe","result":"success"}',
        ),
    ]
    client, _, _ = make_client(script=script)
    row = tar.run_job_lifecycle(client, FakeCtx(), sleep_fn=lambda s: None)
    assert row["status"] == "FAIL"  # honest: expected wipe_refused, got success
    assert row["result"] == "success"


def test_job_lifecycle_poll_deadline_is_bounded():
    def stuck(method, path, headers, body):
        return Resp(200, {}, '{"ok":true,"status":"running","result":null}')

    client, _, clock = make_client(handler=stuck)
    row = tar.run_job_lifecycle(
        client, FakeCtx(), sleep_fn=clock.sleep, poll_timeout_s=5.0, poll_interval_s=1.0
    )
    assert row["status"] == "FAIL"
    assert clock.t <= 10.0  # bounded, no infinite poll


def test_tls_loop_twenty_paced():
    clock = FakeClock()
    ok401 = lambda *a: Resp(401, {}, '{"ok":false,"error":"unauthorized"}')  # noqa: E731
    client, transport, _ = make_client(handler=ok401, clock=clock)
    row = tar.run_tls_handshake_loop(client, FakeCtx(), n=20, sleep_fn=clock.sleep)
    gets = [c for c in transport.calls if c[1] == "/api/status"]
    assert len(gets) == 20
    assert row["status"] == "PASS" and row["ok_401"] == 20
    assert clock.t >= 19.0  # paced >= 1s between handshakes


# ----------------------------------------------------- register(ctx) ----


def firmware_model(clock):
    """Tiny stateful model of the firmware REST surface (rest.rs semantics):
    unknown route 404s before auth, bearer token check, body parse -> 400,
    5s write cooldown -> 429 + Retry-After (recorded only on accepted
    writes), single job slot with an honest wipe_refused result."""
    state = {"last_write": None, "job": "idle"}
    closed_url = re.compile(r'"url"\s*:\s*"[^"]*"')
    closed_key = re.compile(r'"k0"\s*:\s*"[^"]*"')
    expected_auth = "Bearer test-token"

    def handler(method, path, headers, body):
        body_text = body.decode("latin1") if body else ""
        if path == tar.UNKNOWN_ROUTE_PATH:
            return Resp(404, {}, '{"ok":false,"error":"not found"}')
        auth = headers.get("Authorization")
        if auth != expected_auth:
            return Resp(401, {}, '{"ok":false,"error":"unauthorized"}')
        write_route = method == "POST" and path in (
            "/api/keys",
            "/api/url",
            "/api/burn",
            "/api/wipe",
            "/api/job",
        )
        if (
            write_route
            and state["last_write"] is not None
            and clock.t - state["last_write"] < 5.0
        ):
            return Resp(
                429, {"retry-after": "5"}, '{"ok":false,"error":"rate limited"}'
            )
        if path == "/api/url" and not closed_url.search(body_text):
            return Resp(400, {}, '{"ok":false,"error":"missing url"}')
        if path == "/api/keys" and not closed_key.search(body_text):
            return Resp(400, {}, '{"ok":false,"error":"missing k0"}')
        if write_route:
            state["last_write"] = clock.t
        if path == "/api/job":
            if method == "POST":
                state["job"] = "completed-wipe_refused"
                return Resp(201, {}, '{"ok":true,"job_id":1,"status":"pending"}')
            result = (
                '"wipe_refused"' if state["job"] == "completed-wipe_refused" else "null"
            )
            return Resp(
                200,
                {},
                '{"ok":true,"job_id":1,"status":"completed",'
                f'"command":"wipe","result":{result}}}',
            )
        return Resp(200, {}, '{"ok":true}')

    return handler


def test_register_offline_full_suite_fake_ctx(monkeypatch):
    monkeypatch.setenv("REST_IP", "192.0.2.10")
    monkeypatch.setenv("REST_TOKEN", "test-token")
    monkeypatch.delenv("REST_READ_TOKEN", raising=False)
    monkeypatch.delenv("HIL_ISSUER", raising=False)
    monkeypatch.setattr(
        tar, "_derive_keys_via_bolty_cli", fake_derive_bridge(fail=True)
    )
    clock = FakeClock()
    transport = FakeTransport(handler=firmware_model(clock))
    client = tar.RestClient(
        ip="192.0.2.10",
        token="test-token",
        clock=clock,
        transport=transport,
    )
    ctx = FakeCtx()
    tar.register(ctx, client=client, clock=clock)
    # honest SKIPs: gated card endpoints (no staged keys), 429 timing, staging
    skips = {
        r.get("case") or r.get("reason", ""): r
        for r in ctx.rows
        if r.get("status") == "SKIP"
    }
    assert any("CARD-AUTH" in str(v.get("reason", "")) for v in skips.values())
    assert any("429" in str(k) for k in skips), "429 timing must skip w/o keys"
    # no request ever hit a card route (gated) — the firmware model would answer
    card_routes = {
        "/api/keyver",
        "/api/ndef",
        "/api/diagnose",
        "/api/inspect",
        "/api/burn",
        "/api/wipe",
    }
    assert all(c[1] not in card_routes for c in transport.calls)
    # negatives ran (401 x2, 404, 400, 8KB bounded) and the suite PASSed overall
    statuses = {r["status"] for r in ctx.rows}
    assert "FAIL" not in statuses, [r for r in ctx.rows if r["status"] == "FAIL"]
    # job lifecycle completed honestly before any staging POST
    job_rows = [r for r in ctx.rows if r.get("type") == "job_lifecycle"]
    assert job_rows and job_rows[0]["result"] == "wipe_refused"


def test_register_with_staged_keys_runs_gated_endpoints(monkeypatch):
    monkeypatch.setenv("REST_IP", "192.0.2.10")
    monkeypatch.setenv("REST_TOKEN", "test-token")
    monkeypatch.setenv("HIL_ISSUER", "11" * 16)
    monkeypatch.setenv("HIL_UID_STICK", UID_STICK)
    monkeypatch.setattr(tar, "_derive_keys_via_bolty_cli", fake_derive_bridge())
    clock = FakeClock()
    transport = FakeTransport(handler=firmware_model(clock))
    client = tar.RestClient(
        ip="192.0.2.10",
        token="test-token",
        clock=clock,
        transport=transport,
    )
    ctx = FakeCtx()
    led, fed = fake_ledger()
    ctx.ledger = led
    tar.register(ctx, client=client, clock=clock)
    paths = {c[1] for c in transport.calls}
    assert {"/api/keyver", "/api/inspect", "/api/ndef", "/api/diagnose"} <= paths
    assert "/api/burn" in paths and "/api/wipe" in paths
    # card-touching responses fed the ledger model
    assert any(f[0] == "classified" for f in fed)
    fails = [r for r in ctx.rows if r["status"] == "FAIL"]
    assert not fails, fails
    # ordering: job lifecycle (wipe_refused precondition) ran BEFORE key staging
    job_idx = min(i for i, r in enumerate(ctx.rows) if r.get("type") == "job_lifecycle")
    stage_idx = min(i for i, r in enumerate(ctx.rows) if r.get("type") == "stage_keys")
    assert job_idx < stage_idx


def test_register_uses_ctx_card_mutex_for_mutations():
    mp = pytest.MonkeyPatch()
    mp.setenv("REST_IP", "192.0.2.10")
    mp.setenv("REST_TOKEN", "test-token")
    mp.delenv("HIL_ISSUER", raising=False)
    mp.setattr(tar, "_derive_keys_via_bolty_cli", fake_derive_bridge(fail=True))
    clock = FakeClock()
    lock = FakeCardLock()
    seen_depth = []
    base_handler = firmware_model(clock)

    def spy(method, path, headers, body):
        seen_depth.append((method, path, lock.depth))
        return base_handler(method, path, headers, body)

    client = tar.RestClient(
        ip="192.0.2.10",
        token="test-token",
        clock=clock,
        transport=FakeTransport(handler=spy),
    )
    tar.register(FakeCtx(lock=lock), client=client, clock=clock)
    mp.undo()
    mutating = [
        d
        for m, p, d in seen_depth
        if m == "POST" and p in ("/api/keys", "/api/burn", "/api/wipe", "/api/job")
    ]
    url_depths = [d for m, p, d in seen_depth if p == "/api/url"]
    # the positive url staging (valid body) ran under the lock; the
    # malformed-JSON middleware negative correctly did not
    assert any(d > 0 for d in url_depths), seen_depth
    assert any(d == 0 for d in url_depths), seen_depth
    assert mutating and all(d > 0 for d in mutating), seen_depth
    assert lock.acquisitions.count("stick") >= 1


def test_register_standalone_mode_without_rest_ip(monkeypatch):
    monkeypatch.delenv("REST_IP", raising=False)
    ctx = FakeCtx()
    tar.register(ctx, client=None, clock=FakeClock())
    assert len(ctx.rows) == 1 and ctx.rows[0]["status"] == "SKIP"
    assert "REST_IP" in ctx.rows[0]["reason"]


def test_build_lane_shape():
    lane = tar.build_lane()
    assert lane.name == "track_a_rest"
    assert lane.window == "window1"
    assert "stick" in lane.cards


# ----------------------------------------------------------- selftest ----


def test_selftest_cli_offline():
    mod = Path(tar.__file__).resolve()
    proc = subprocess.run(
        [sys.executable, str(mod), "--selftest"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "REST_IP": ""},  # standalone: no network attempted
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "selftest" in proc.stdout.lower()
    assert "13" in proc.stdout  # route count reported


def test_module_never_imports_requests():
    # harness constraint: stdlib + pyserial + pyscard only (plan todo 5)
    src = Path(tar.__file__).read_text(encoding="utf-8")
    assert not re.search(r"^\s*import requests|^\s*from requests", src, re.M)
