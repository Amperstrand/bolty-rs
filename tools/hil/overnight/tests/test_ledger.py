#!/usr/bin/env python3
"""Tests for the overnight card-safety ledger + circuit breaker.

Pure-logic TDD suite (plan todo 6): threshold trips, failure
classification, persistence, fail-closed corruption handling, exclusion
list, UID assertion, recovery-key contract. No hardware, no network, no
subprocess — the bolty-cli derivation bridge is monkeypatched.

Run:  cd /home/ubuntu/src/bolty-rs && \
      python3 -m pytest tools/hil/overnight/tests/test_ledger.py -q
"""

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ledger  # noqa: E402
from ledger import (  # noqa: E402
    EXCLUSION_LIST,
    CardSafetyHalt,
    ExcludedCardError,
    Ledger,
    UidMismatchError,
    assert_target_uid,
    classify_output,
)

UID_STICK = "04C474FA967380"  # stick card (blank lab stock)
UID_ACR = "040C60FA967380"  # ACR1252 card
UID_STUCK = "043365FA967380"  # excluded unknown-key card (AGENTS.md)


# ---------------------------------------------------------------- classification


def test_classify_auth_fail_on_91ae_and_91ad():
    assert classify_output("error: card rejected auth: 91AE") == "auth_fail"
    assert classify_output("Auth delay (91AD) — keep trying (1/20)...") == "auth_fail"
    assert classify_output("rest /api/keyver -> authentication failed") == "auth_fail"
    assert classify_output("91ae") == "auth_fail"  # case-insensitive


def test_classify_hex_payload_substring_is_not_auth_fail():
    # 32-hex picc/SDM payload CONTAINING "91ae" must not false-positive
    # (word boundaries, mirrors real console `picc` output).
    assert (
        classify_output("url p=AB91AEBF0123456789ABCDEF01234567&c=00112233 sdm=ok")
        == "ok"
    )


def test_classify_transport_patterns():
    assert classify_output("reader not found") == "transport"
    assert classify_output("no readers available") == "transport"
    assert classify_output("SCARD_E_NO_READERS_AVAILABLE") == "transport"
    assert classify_output("pcscd: connection refused") == "transport"
    assert classify_output("bolty-cli: timed out waiting for card") == "transport"
    assert classify_output("operation timeout after 30s") == "transport"
    assert classify_output("serial port disruption mid-flash") == "transport"


def test_classify_ok_on_poll_markers():
    assert classify_output("REQA ok") == "ok"
    assert classify_output("WUPA poll: card present") == "ok"
    assert classify_output("OK uid=04C474FA967380") == "ok"
    assert classify_output("picc sdm=ok uid_match=true") == "ok"


def test_classify_unknown_and_precedence():
    assert classify_output("") == "unknown"
    assert classify_output("random console chatter 123") == "unknown"
    # documented precedence: an OBSERVED card verdict (91AE) beats transport
    # noise in the same text block — the card really did reject.
    assert classify_output("91AE then reader not found on retry") == "auth_fail"


# ---------------------------------------------------------------- thresholds


def test_exact_trip_at_10_consecutive_not_at_9(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    for _ in range(9):
        led.record_auth_failure(UID_STICK)
    led.assert_may_proceed(UID_STICK)  # 9 consecutive: must NOT trip
    led.record_auth_failure(UID_STICK)  # 10th consecutive
    with pytest.raises(CardSafetyHalt) as ei:
        led.assert_may_proceed(UID_STICK)
    exc = ei.value
    assert exc.card == UID_STICK
    assert exc.reason == "consecutive_limit"
    assert exc.counters["consecutive_failures"] == 10


def test_exact_trip_at_50_total_not_at_49(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    for _ in range(5):  # 45 failures; success keeps consecutive < 10
        for _ in range(9):
            led.record_auth_failure(UID_STICK)
        led.record_auth_success(UID_STICK)
    for _ in range(4):
        led.record_auth_failure(UID_STICK)  # 49 total, 5 consecutive
    led.assert_may_proceed(UID_STICK)  # 49 total: must NOT trip
    led.record_auth_failure(UID_STICK)  # 50th total
    with pytest.raises(CardSafetyHalt) as ei:
        led.assert_may_proceed(UID_STICK)
    assert ei.value.reason == "total_limit"
    assert ei.value.counters["total_failures"] == 50


def test_halt_is_per_card_only(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    for _ in range(10):
        led.record_auth_failure(UID_STICK)
    with pytest.raises(CardSafetyHalt) as ei:
        led.assert_may_proceed(UID_STICK)
    assert ei.value.card == UID_STICK  # exception carries the card id
    led.assert_may_proceed(UID_ACR)  # other card's track keeps running
    led.record_auth_failure(UID_ACR)  # and can still record


def test_counter_semantics_auth_attempts(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    for _ in range(9):
        led.record_auth_failure(UID_ACR)
    c = led.counters(UID_ACR)
    assert c["auth_attempts"] == 9
    assert c["consecutive_failures"] == 9
    assert c["total_failures"] == 9
    led.record_auth_success(UID_ACR)
    c = led.counters(UID_ACR)
    assert c["auth_attempts"] == 10
    assert c["consecutive_failures"] == 0  # success clears consecutive
    assert c["total_failures"] == 9  # total never decreases
    led.record_auth_failure(UID_ACR)
    c = led.counters(UID_ACR)
    assert (c["auth_attempts"], c["consecutive_failures"], c["total_failures"]) == (
        11,
        1,
        10,
    )
    led.record_op(UID_ACR, "burn")
    led.record_op(UID_ACR, "burn")
    led.record_op(UID_ACR, "wipe")
    assert led.counters(UID_ACR)["ops_by_type"] == {"burn": 2, "wipe": 1}


def test_transport_events_never_touch_counters_but_are_journaled(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    for _ in range(100):  # a whole night of reader flaps
        led.record_transport_event(UID_STICK, "reader not found; timed out")
    c = led.counters(UID_STICK)
    assert c == {
        "auth_attempts": 0,
        "consecutive_failures": 0,
        "total_failures": 0,
        "ops_by_type": {},
    }
    led.assert_may_proceed(UID_STICK)  # never trips on transport
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    assert len(lines) == 100
    assert all(json.loads(ln)["event"] == "transport" for ln in lines)


def test_record_classified_routes_by_classification(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    assert led.record_classified(UID_STICK, "91AE") == "auth_fail"
    assert led.record_classified(UID_STICK, "reader not found") == "transport"
    assert led.record_classified(UID_STICK, "REQA ok") == "ok"
    c = led.counters(UID_STICK)
    assert c["total_failures"] == 1  # only the auth_fail observation counted
    assert c["consecutive_failures"] == 1


# ---------------------------------------------------------------- persistence


def test_atomic_persist_after_every_event(tmp_path):
    path = tmp_path / "ledger.json"
    led = Ledger(path)
    led.record_auth_failure(UID_STICK)
    on_disk = json.loads(path.read_text())
    assert on_disk["cards"][UID_STICK]["total_failures"] == 1
    led.record_auth_failure(UID_STICK)
    on_disk = json.loads(path.read_text())
    assert on_disk["cards"][UID_STICK]["total_failures"] == 2
    led.record_auth_success(UID_STICK)
    on_disk = json.loads(path.read_text())
    assert on_disk["cards"][UID_STICK]["consecutive_failures"] == 0
    assert not list(tmp_path.glob("*.tmp"))  # no temp-file leftovers


def test_reload_survival_round_trip(tmp_path):
    path = tmp_path / "ledger.json"
    led = Ledger(path, excluded=["04AABBCCDD0011"])
    for _ in range(7):
        led.record_auth_failure(UID_STICK)
    led.record_auth_success(UID_STICK)
    led.record_auth_failure(UID_STICK)
    led.record_op(UID_ACR, "burn")
    led2 = Ledger(path)
    assert led2.counters(UID_STICK) == led.counters(UID_STICK)
    assert led2.counters(UID_ACR) == led.counters(UID_ACR)
    assert led2.is_excluded(UID_STUCK)  # module list persisted
    assert led2.is_excluded("04AABBCCDD0011")  # extra entries persisted
    # breaker state survives reload: consecutive is 1 after reload, 9 more trip it
    for _ in range(9):
        led2.record_auth_failure(UID_STICK)
    with pytest.raises(CardSafetyHalt):
        led2.assert_may_proceed(UID_STICK)


def test_corrupt_ledger_fails_closed_and_rebuilds_from_journal(tmp_path):
    path = tmp_path / "ledger.json"
    led = Ledger(path)
    for _ in range(3):
        led.record_auth_failure(UID_STICK)
    led.record_op(UID_ACR, "burn")
    path.write_text('{"broken": nope')  # corrupt the snapshot
    led2 = Ledger(path)
    # rebuilt from the append-only journal sidecar
    assert led2.counters(UID_STICK)["total_failures"] == 3
    assert led2.counters(UID_ACR)["ops_by_type"] == {"burn": 1}
    # FAIL-CLOSED: card ops halt (not silent continue), for every card
    with pytest.raises(CardSafetyHalt) as ei:
        led2.assert_may_proceed(UID_STICK)
    assert "corrupt" in ei.value.reason
    with pytest.raises(CardSafetyHalt):
        led2.assert_may_proceed(UID_ACR)  # even a zero-count card halts


# ---------------------------------------------------------------- exclusion list


def test_exclusion_list_contains_stuck_card():
    assert "043365FA967380" in EXCLUSION_LIST


def test_excluded_uid_rejected_case_insensitive(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    assert led.is_excluded(UID_STUCK)
    with pytest.raises(ExcludedCardError) as ei:
        led.assert_may_proceed(UID_STUCK.lower())  # console-case variants
    assert ei.value.card == UID_STUCK  # normalized uppercase
    with pytest.raises(ExcludedCardError):
        led.recovery_key(UID_STUCK.lower())
    led.assert_may_proceed(UID_STICK)  # non-excluded cards unaffected


# ---------------------------------------------------------------- UID assertion


def test_assert_target_uid_case_insensitive_and_embedded():
    assert_target_uid("043365fa967380", "043365FA967380", "poll")
    assert_target_uid("04C474FA967380", "04c474fa967380", "burn")
    # raw console line containing the uid (burn_cycle substring semantics)
    assert_target_uid("OK uid=04C474FA967380 nfc=ok", "04C474FA967380", "console")


def test_assert_target_uid_mismatch_raises_with_context():
    with pytest.raises(UidMismatchError) as ei:
        assert_target_uid("04C474FA967380", UID_STUCK, "pre-burn gate")
    assert ei.value.observed.startswith("04C474FA967380")
    assert ei.value.expected == UID_STUCK
    assert "pre-burn gate" in str(ei.value)


# ---------------------------------------------------------------- recovery key


def test_recovery_key_returns_only_derived_k0(tmp_path, monkeypatch):
    monkeypatch.delenv("HIL_ISSUER", raising=False)
    calls = {}

    def fake_derive(issuer_key, uid, version):
        calls.update(issuer_key=issuer_key, uid=uid, version=version)
        return {"ok": True, "version": version, "card_key": "cd" * 16, "k0": "ab" * 16}

    monkeypatch.setattr(ledger, "_derive_keys_via_bolty_cli", fake_derive)
    issuer = (
        "0" * 31 + "1"
    )  # well-known PUBLIC dev issuer (burn_cycle.py), not a secret
    led = Ledger(tmp_path / "ledger.json", issuer_key=issuer, key_version=1)
    assert led.recovery_key(UID_STICK.lower()) == "ab" * 16
    assert calls == {"issuer_key": issuer, "uid": UID_STICK, "version": 1}
    # no issuer configured -> refuse rather than fall back to any embedded key
    led_bare = Ledger(tmp_path / "l2.json")
    with pytest.raises(ledger.LedgerConfigError):
        led_bare.recovery_key(UID_STICK)


# ---------------------------------------------------------------- static audit


def test_static_audit_no_key_literals_no_trykey_invocation():
    # Plan F4 grep-audit, enforced as a test: harness sources contain no raw
    # 32-hex key material and never invoke try-key/try_key with anything.
    harness_dir = Path(__file__).resolve().parents[1]
    sources = sorted(harness_dir.glob("*.py"))
    assert sources, "harness sources must exist"
    for src in sources:
        text = src.read_text()
        assert not re.search(r"['\"]try[-_]key['\"]", text), (
            f"{src.name}: try-key invocation"
        )
        assert not re.search(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])", text), (
            f"{src.name}: raw 32-hex key literal"
        )
