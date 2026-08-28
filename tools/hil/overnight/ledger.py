#!/usr/bin/env python3
"""Overnight HIL card-safety ledger + circuit breaker (plan todo 6).

The NTAG424 DNA failed-auth counters cannot be read from the card
(SeqFailCtr 50 -> 91AD delay, TotFailCtr 1000 -> PERMANENT key lock;
bolty-rs/AGENTS.md "Card Recovery"), so the harness keeps its own
conservative MODEL and halts a card's track far below the hardware brick
limits:

    consecutive observed auth failures >= DEFAULT_CONSECUTIVE_LIMIT (10)   vs 50  on-card
    total      observed auth failures >= DEFAULT_TOTAL_LIMIT      (50)   vs 1000 on-card

FAILURE CLASSIFICATION IS LOAD-BEARING: only observed card-auth rejections
(91AE AuthFailed / 91AD AuthDelay in command output or console text) count
as failures. Transport errors (reader absent, pcscd down, port disruption,
timeouts) are journaled but NEVER touch card counters — an unreachable
card cannot have rejected anything.

Proven-safe envelope (user decision 2026-08-28): no deliberate wrong-key
authentication exists in this harness. recovery_key() can only return the
deterministic K0 derived from the CONFIGURED issuer key via
`bolty-cli derive-keys` — no key material is ever embedded here.
"""

import json
import os
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "EXCLUSION_LIST",
    "DEFAULT_CONSECUTIVE_LIMIT",
    "DEFAULT_TOTAL_LIMIT",
    "CardSafetyError",
    "CardSafetyHalt",
    "ExcludedCardError",
    "UidMismatchError",
    "LedgerConfigError",
    "Ledger",
    "normalize_uid",
    "classify_output",
    "assert_target_uid",
]

DEFAULT_CONSECUTIVE_LIMIT = 10
DEFAULT_TOTAL_LIMIT = 50

# Stuck unknown-key card (AGENTS.md Card Recovery) — never a mutation target.
EXCLUSION_LIST = ["043365FA967380"]

_ISSUER_KEY_RE = re.compile(r"[0-9a-f]{32}")
_UID_RE = re.compile(r"[0-9A-F]{14}")  # NTAG424 7-byte UID
_UID_CLEAN_RE = re.compile(r"[\s:]")

# Word boundaries keep hex payloads (picc p=.../c=..., URL params) that merely
# CONTAIN "91ae" as a substring from false-positiving as card verdicts.
_AUTH_FAIL_RES = (
    re.compile(r"(?i)\b91ae\b"),
    re.compile(r"(?i)\b91ad\b"),
    re.compile(r"(?i)auth(entication)?\s+fail"),
)
_TRANSPORT_RES = (
    re.compile(r"(?i)reader\s+not\s+found"),
    re.compile(r"(?i)no\s+(smart\s*card\s+)?readers?"),
    re.compile(r"(?i)\bpcscd?\b"),
    re.compile(r"(?i)\bscard_e_\w+"),
    re.compile(r"(?i)\btimeout"),
    re.compile(r"(?i)\btimed out\b"),
    re.compile(r"(?i)\bport\b"),
    re.compile(r"(?i)connection\s+(refused|reset|closed)"),
    re.compile(r"(?i)\bno card\b|card\s+(not\s+present|absent)"),
)
_OK_RES = (
    re.compile(r"(?i)\breqa\b"),
    re.compile(r"(?i)\bwupa\b"),
    re.compile(r"(?i)\bpoll\b"),
    re.compile(r"(?i)sdm=ok\b"),
    re.compile(r"(?i)uid_match=true"),
    re.compile(r"(?im)^ok\b"),
)


def normalize_uid(uid):
    """Uppercase + strip whitespace/colons/0x (console prints uppercase,
    pcsc readers vary; comparisons are always case-insensitive)."""
    cleaned = _UID_CLEAN_RE.sub("", str(uid).strip()).upper()
    return cleaned[2:] if cleaned.startswith("0X") else cleaned


def classify_output(text):
    """Classify command output / console text: 'auth_fail' | 'transport' | 'ok' | 'unknown'.

    Precedence: an observed card verdict (91AE/91AD/auth-failed phrase) wins
    over transport noise in the same block — if the card answered, the
    rejection is real. Transport alone means the card was never reached, so
    no card verdict exists and counters never move. 'unknown' is the safe
    default for unrecognized text (also never counted).
    """
    if not text:
        return "unknown"
    if any(r.search(text) for r in _AUTH_FAIL_RES):
        return "auth_fail"
    if any(r.search(text) for r in _TRANSPORT_RES):
        return "transport"
    if any(r.search(text) for r in _OK_RES):
        return "ok"
    return "unknown"


def assert_target_uid(observed_uid, expected_uid, context=""):
    """Harness-side UID gate — call before EVERY card mutation.

    The wrapped tools have no --confirm-uid (burn_cycle uses the HIL_UID
    env; bolty-cli checks internally), so the harness enforces the expected
    card here. Matching is case-insensitive; a raw console/reader line
    containing the expected uid is accepted (burn_cycle.py substring
    semantics). Raises UidMismatchError on any mismatch.
    """
    expected = normalize_uid(expected_uid)
    observed_raw = "" if observed_uid is None else str(observed_uid)
    if expected and expected in normalize_uid(observed_raw):
        return
    raise UidMismatchError(observed_raw, expected, context)


class CardSafetyError(Exception):
    """Base class for card-safety refusals raised by this module."""


class CardSafetyHalt(CardSafetyError):
    """Circuit breaker tripped (or ledger corrupt): halt THIS card's track only.

    The card uid rides on the exception so sibling tracks keep running
    their own cards. `reason` is 'consecutive_limit' | 'total_limit' |
    'ledger_corrupt_fail_closed'; `counters` is a snapshot at raise time.
    """

    def __init__(self, card, reason, counters=None, message=None):
        self.card = card
        self.reason = reason
        self.counters = {
            "auth_attempts": (counters or {}).get("auth_attempts", 0),
            "consecutive_failures": (counters or {}).get("consecutive_failures", 0),
            "total_failures": (counters or {}).get("total_failures", 0),
            "ops_by_type": dict((counters or {}).get("ops_by_type", {})),
        }
        super().__init__(message or f"card {card}: safety halt ({reason})")


class ExcludedCardError(CardSafetyError):
    """Mutation attempted on an EXCLUSION_LIST card — never a target."""

    def __init__(self, card):
        self.card = card
        super().__init__(
            f"card {card} is on the exclusion list and must never be a mutation target"
        )


class UidMismatchError(CardSafetyError):
    """assert_target_uid observed a different card than expected."""

    def __init__(self, observed, expected, context=""):
        self.observed = observed
        self.expected = expected
        self.context = context
        where = f" [{context}]" if context else ""
        super().__init__(
            f"UID mismatch{where}: expected {expected}, observed {observed}"
        )


class LedgerConfigError(CardSafetyError):
    """Ledger is not configured for the requested operation (e.g. no issuer key)."""


def _zero_counters():
    return {
        "auth_attempts": 0,
        "consecutive_failures": 0,
        "total_failures": 0,
        "ops_by_type": {},
    }


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _derive_keys_via_bolty_cli(issuer_key, uid, version, binary="bolty-cli"):
    """Derivation bridge: shell out to `bolty-cli derive-keys` (pure stdlib).

    The deterministic AES-CMAC diversification lives in bolty-core
    (BoltcardDeterministicDeriver) — this harness never re-implements it
    and never embeds key material. Runs the documented stub command

        bolty-cli derive-keys --json --uid <uid> --issuer-key <issuer> --version <n>

    and parses the single JSON line bolty-cli prints (apps/bolty-cli/src/
    main.rs, Cli::DeriveKeys): {"ok":true,"version":<v>,"card_key":"<32hex>",
    "k0":"<32hex>","k1":...}. derive-keys touches no card — it is pure
    computation.
    """
    cmd = [
        binary,
        "derive-keys",
        "--json",
        "--uid",
        uid,
        "--issuer-key",
        issuer_key,
        "--version",
        str(version),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode != 0:
        raise LedgerConfigError(
            f"{binary} derive-keys failed rc={proc.returncode}: {proc.stderr.strip()[:200]}"
        )
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            keys = json.loads(line)
            if keys.get("ok"):
                return keys
            break
    raise LedgerConfigError(f"{binary} derive-keys produced no parsable JSON key line")


class Ledger:
    """Per-card auth-failure model with atomic persistence and a breaker.

    Files (side by side in `path`'s directory):
      ledger.json   — counter snapshot, atomically rewritten (write-temp +
                      os.replace) after EVERY event
      ledger.jsonl  — append-only event journal; the rebuild source when
                      the snapshot is corrupt (fail-closed: card ops halt,
                      state is rebuilt from this journal, never silently
                      reset)

    Tracks call assert_may_proceed(card) before every mutation; the raised
    CardSafetyHalt/ExcludedCardError halts only that card's track.
    """

    def __init__(
        self,
        path,
        *,
        issuer_key=None,
        key_version=None,
        consecutive_limit=DEFAULT_CONSECUTIVE_LIMIT,
        total_limit=DEFAULT_TOTAL_LIMIT,
        excluded=None,
    ):
        self.path = Path(path)
        suffix = (
            ".jsonl" if self.path.suffix == ".json" else self.path.suffix + ".jsonl"
        )
        self.journal_path = self.path.with_suffix(suffix)
        self.consecutive_limit = int(consecutive_limit)
        self.total_limit = int(total_limit)
        self.issuer_key = (
            issuer_key if issuer_key is not None else os.environ.get("HIL_ISSUER")
        )
        raw_version = (
            key_version
            if key_version is not None
            else os.environ.get("HIL_KEY_VERSION")
        )
        try:
            self.key_version = int(raw_version) if raw_version is not None else 1
        except ValueError as exc:
            raise LedgerConfigError(f"invalid key version {raw_version!r}") from exc
        self._excluded_extra = {normalize_uid(u) for u in (excluded or [])}
        self._excluded_file = set()
        self._cards = {}
        self._lock = threading.Lock()
        self._corrupt = False
        self._load()

    # ------------------------------------------------------------------ load

    def _load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            cards = data["cards"]
            if not isinstance(cards, dict):
                raise ValueError("cards must be an object")
        except (OSError, ValueError, KeyError, TypeError):
            # FAIL-CLOSED: a corrupt snapshot halts card ops for the lifetime
            # of this instance; counters are rebuilt from the journal so no
            # observed failure is lost. Never silently continue from zero.
            self._corrupt = True
            self._rebuild_from_journal()
            return
        for uid, ctr in cards.items():
            card = _zero_counters()
            card["auth_attempts"] = int(ctr.get("auth_attempts", 0))
            card["consecutive_failures"] = int(ctr.get("consecutive_failures", 0))
            card["total_failures"] = int(ctr.get("total_failures", 0))
            card["ops_by_type"] = {
                str(k): int(v) for k, v in dict(ctr.get("ops_by_type", {})).items()
            }
            self._cards[normalize_uid(uid)] = card
        persisted = data.get("excluded", [])
        if isinstance(persisted, list):
            self._excluded_file = {normalize_uid(u) for u in persisted}

    def _rebuild_from_journal(self):
        if not self.journal_path.exists():
            return
        raw = self.journal_path.read_text(encoding="utf-8", errors="replace")
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                self._apply_event(event.get("event"), event)
            except (ValueError, KeyError, TypeError):
                # torn/partial journal tail: skip — halt is already sticky
                continue

    def _apply_event(self, event, ev):
        if event not in ("auth_failure", "auth_success", "op"):
            return  # transport + ledger_corrupt rows never touch counters
        card = self._cards.setdefault(normalize_uid(ev["card"]), _zero_counters())
        if event == "auth_failure":
            card["auth_attempts"] += 1
            card["consecutive_failures"] += 1
            card["total_failures"] += 1
        elif event == "auth_success":
            card["auth_attempts"] += 1
            card["consecutive_failures"] = 0
        else:
            op = str(ev.get("op", "unknown"))
            card["ops_by_type"][op] = card["ops_by_type"].get(op, 0) + 1

    # ---------------------------------------------------------------- record

    def record_auth_failure(self, card):
        """Record ONE observed card-auth rejection.

        Feed this EXCLUSIVELY from classify_output(text) == 'auth_fail'
        (91AE/91AD semantics) — e.g. via record_classified().
        """
        card = normalize_uid(card)
        with self._lock:
            self._apply_event("auth_failure", {"card": card})
            self._journal({"event": "auth_failure", "card": card})
            self._persist()

    def record_auth_success(self, card):
        """A successful auth clears consecutive failures; total never decreases."""
        card = normalize_uid(card)
        with self._lock:
            self._apply_event("auth_success", {"card": card})
            self._journal({"event": "auth_success", "card": card})
            self._persist()

    def record_op(self, card, op):
        """Count a card operation under ops_by_type (e.g. 'burn', 'wipe')."""
        card = normalize_uid(card)
        with self._lock:
            self._apply_event("op", {"card": card, "op": op})
            self._journal({"event": "op", "card": card, "op": op})
            self._persist()

    def record_transport_event(self, card, text=""):
        """Journal a transport error. NEVER touches card counters."""
        card = normalize_uid(card)
        with self._lock:
            self._journal(
                {"event": "transport", "card": card, "detail": str(text)[:200]}
            )
            self._persist()

    def record_classified(self, card, text):
        """Classify command output, then route it:
        auth_fail -> card counters, transport -> journal only,
        ok/unknown -> nothing (safe default). Returns the classification.
        """
        kind = classify_output(text)
        if kind == "auth_fail":
            self.record_auth_failure(card)
        elif kind == "transport":
            self.record_transport_event(card, text)
        return kind

    # ------------------------------------------------------------------ gate

    def assert_may_proceed(self, card):
        """Gate EVERY card mutation through this.

        Raises ExcludedCardError for exclusion-list cards, CardSafetyHalt
        when the breaker is tripped (consecutive >= limit OR total >=
        limit) or when the persisted ledger was corrupt (fail-closed).
        The halt covers only THIS card — siblings keep their tracks.
        """
        card = normalize_uid(card)
        if self.is_excluded(card):
            raise ExcludedCardError(card)
        if self._corrupt:
            raise CardSafetyHalt(
                card,
                "ledger_corrupt_fail_closed",
                self._cards.get(card),
                message=(
                    f"card {card}: safety halt (ledger_corrupt_fail_closed) — "
                    f"persisted ledger was corrupt; state rebuilt from journal, "
                    f"card ops must not resume in this process"
                ),
            )
        counters = self._cards.get(card, _zero_counters())
        if counters["consecutive_failures"] >= self.consecutive_limit:
            raise CardSafetyHalt(
                card,
                "consecutive_limit",
                counters,
                message=(
                    f"card {card}: safety halt (consecutive_limit "
                    f"{counters['consecutive_failures']}>={self.consecutive_limit}; "
                    f"card SeqFailCtr brick limit is 50)"
                ),
            )
        if counters["total_failures"] >= self.total_limit:
            raise CardSafetyHalt(
                card,
                "total_limit",
                counters,
                message=(
                    f"card {card}: safety halt (total_limit "
                    f"{counters['total_failures']}>={self.total_limit}; "
                    f"card TotFailCtr brick limit is 1000)"
                ),
            )

    def is_excluded(self, card):
        return normalize_uid(card) in self._exclusion_set()

    def _exclusion_set(self):
        return (
            {normalize_uid(u) for u in EXCLUSION_LIST}
            | self._excluded_extra
            | self._excluded_file
        )

    def counters(self, card):
        with self._lock:
            card_counters = self._cards.get(normalize_uid(card))
        if card_counters is None:
            return _zero_counters()
        return {
            "auth_attempts": card_counters["auth_attempts"],
            "consecutive_failures": card_counters["consecutive_failures"],
            "total_failures": card_counters["total_failures"],
            "ops_by_type": dict(card_counters["ops_by_type"]),
        }

    # ---------------------------------------------------------------- recover

    def recovery_key(self, card):
        """The ONLY key recovery/try-key may ever be invoked with.

        Returns the deterministic K0 for this card derived from the
        CONFIGURED issuer key (issuer_key= / HIL_ISSUER env) via
        `bolty-cli derive-keys` (_derive_keys_via_bolty_cli stub). No other
        key can be produced here: none exists in this module. Raises
        ExcludedCardError for excluded cards, LedgerConfigError when no
        valid issuer key is configured, ValueError on a malformed uid.
        """
        card = normalize_uid(card)
        if self.is_excluded(card):
            raise ExcludedCardError(card)
        issuer = (self.issuer_key or "").strip().lower()
        if not _ISSUER_KEY_RE.fullmatch(issuer):
            raise LedgerConfigError(
                "recovery_key requires a configured 32-hex issuer key "
                "(issuer_key= or HIL_ISSUER) — no fallback key exists"
            )
        if not _UID_RE.fullmatch(card):
            raise ValueError(f"card uid {card!r} is not a 14-hex (7-byte) uid")
        keys = _derive_keys_via_bolty_cli(issuer, card, self.key_version)
        k0 = str(keys.get("k0", "")).strip().lower()
        if not _ISSUER_KEY_RE.fullmatch(k0):
            raise LedgerConfigError(
                f"bolty-cli derive-keys returned no usable k0 for {card}"
            )
        return k0

    # ---------------------------------------------------------------- persist

    def _persist(self):
        # caller holds self._lock; write-temp + os.replace = atomic swap
        data = {
            "version": 1,
            "updated": _utcnow_iso(),
            "limits": {
                "consecutive": self.consecutive_limit,
                "total": self.total_limit,
            },
            "excluded": sorted(self._exclusion_set()),
            "cards": self._cards,
        }
        tmp = self.path.parent / (self.path.name + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def _journal(self, event):
        # caller holds self._lock; append-only sidecar ledger.jsonl
        record = {"ts": _utcnow_iso(), **event}
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.journal_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
