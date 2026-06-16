# NTAG424 DNA Card Safety Reference

## Overview

This document catalogues safe and unsafe operations on NTAG424 DNA cards,
with specific focus on bolt card provisioning workflows. It is based on:
- NXP NTAG424 DNA Product Data Sheet (Rev. 3.0, NT4H2421Gx)
- NXP Application Note AN12196 (Features and Hints)
- Proxmark3 NTAG424 implementation (client/src/cmdhfntag424.c)
- bolty-rs source code analysis (burn.rs, wipe.rs, diagnose.rs, bolty-ntag)

---

## 1. Card States

| State | K0 | K1-K4 | SDM | NDEF | Key Versions |
|-------|-----|-------|-----|------|--------------|
| **FACTORY (blank)** | `0000...0000` | `0000...0000` | disabled | empty (NLEN=0) | all `0x00` |
| **PROVISIONED** | derived | derived | enabled | URL template + SDM placeholders | all `0x01` (or set version) |
| **HALF-WIPED** | factory | derived | disabled | empty | mixed (K0=0x00, K1-K4=0x01) |
| **HALF-BURNED** | factory | some derived | enabled or disabled | written | mixed |
| **AUTH-DELAYED** | unknown | unknown | unknown | unknown | unknown — card temporarily unresponsive |

### State Detection Heuristics (used by `diagnose` command)

1. **Read UID** (unauthenticated) — always safe
2. **GetVersion** (unauthenticated) — confirms NTAG424 chip type
3. **GetFileSettings** on NDEF file (unauthenticated) — SDM presence indicates provisioned
4. **Read NDEF** (unauthenticated) — content presence indicates provisioned
5. **Factory K0 probe** — single AES auth attempt with zeros key; success = blank/half-wiped
6. **SDM PICC decrypt** — local computation from NDEF p=/c= params; no card interaction

**Key insight**: Steps 1-4 and 6 are completely safe (zero authentication APDUs).
Step 5 sends one auth APDU; if it fails, the card increments its failed-auth counter.

---

## 2. Safe Operations (Zero Risk of Bricking)

These operations CANNOT brick the card or cause permanent damage:

| Operation | Auth Required | Risk |
|-----------|--------------|------|
| Read UID (`get_selected_uid`) | None | None |
| GetVersion | None | None |
| GetFileSettings (NDEF) | None | None |
| Read NDEF file (unauthenticated) | None | None |
| Read NDEF file (plain, with auth) | K0 or configured read key | None |
| SDM PICC decryption (local computation) | None (reads NDEF only) | None |
| Key derivation (local computation) | None (no card interaction) | None |

### Why These Are Safe
- No writes to card EEPROM
- No key changes
- No file settings changes
- Cannot trigger authentication delay (unauthenticated reads skip the auth subsystem)
- Cannot corrupt card state

---

## 3. Unsafe Operations (Risk of Bricking or Lockout)

### 3.1 CRITICAL: Master Key (K0) Loss — PERMANENT BRICK

**Severity**: CATASTROPHIC — card is permanently unusable.

The AppMasterKey (K0, key number 0) is required to change ANY application key.
If K0 is changed to an unknown value, the card is permanently locked:
- Cannot change any key (requires K0 auth)
- Cannot reset to factory (requires K0 auth)
- Cannot reconfigure file settings that require Change key (requires K0 auth)
- **No recovery mechanism exists** — NXP does not provide a factory reset without K0

**Prevention in bolty-rs**: K0 is changed LAST in the burn sequence (step 7/7).
Until that step, factory K0 still works for recovery.

### 3.2 HIGH: ChangeKey on K1-K4 — Reversible If K0 Known

**Severity**: HIGH if K0 unknown, LOW if K0 is still factory.

Changing K1-K4 to wrong values makes SDM verification fail, but:
- If K0 is still factory: re-burn fixes everything (auth with factory K0, re-install keys)
- If K0 has been changed: requires knowing K0 to fix (same as 3.1)

**Prevention in bolty-rs**: K1-K4 are changed before K0. If any K1-K4 change fails,
the error message reports the card state and recovery procedure.

### 3.3 MEDIUM: SDM Misconfiguration — Recoverable

**Severity**: MEDIUM — card appears broken but is recoverable with K0.

Wrong SDM offsets or wrong SDM key assignment causes:
- NDEF reads return garbage or empty data
- SDM verification fails (wrong CMAC, wrong encrypted PICC data)
- Phone scans produce invalid URLs

This does NOT brick the card — reconfiguring SDM with correct settings fixes it.
Requires K0 authentication to change file settings.

### 3.4 MEDIUM: Authentication Delay — Temporary Lockout

**Severity**: MEDIUM — temporary, self-resolving.

After repeated failed authentication attempts, the card enters Authentication Delay:
- Returns status code `91AE` (Authentication Error) with delay indicator
- Card refuses all authenticated commands for a period
- Delay duration escalates with consecutive failures
- Delay clears after a successful authentication or by "keep trying" (rapid AuthFirst within same connection)

**Typical trigger**: Probing with wrong keys during state detection.

**Prevention in bolty-rs**: Auth delay is detected via `is_auth_delay()`. When detected,
the code waits 1 second and retries. The `LoggingTransport` records all auth attempts
to `/tmp/bolty-audit.log` for debugging.

### 3.5 LOW: NDEF Content Corruption — Fully Recoverable

Writing wrong data to the NDEF file produces a card that scans to the wrong URL,
but does not affect cryptographic keys or SDM configuration. Rewriting NDEF fixes it.

### 3.6 LOW: File Settings Change — Recoverable

Changing access rights can make files temporarily unreadable, but with K0 auth,
file settings can always be reconfigured. The only permanent lock is losing K0 itself.

---

## 4. Burn APDU Sequence Analysis

The `cmd_burn` function in `apps/bolty-cli/src/burn.rs` executes this sequence:

| Step | Operation | Auth | Reversible? | Failure Recovery |
|------|-----------|------|-------------|------------------|
| Pre | Read UID | None | N/A | Retry |
| 1/7 | Authenticate K0 (factory or derived) | K0 | Yes | Retry with other key |
| 1b | Clear residual SDM (if present) | K0 | Yes | Re-run burn |
| 2/7 | Write NDEF template | K0 | Yes | Re-write NDEF |
| 2b | Read back NDEF to verify | K0 | Yes | Re-write NDEF |
| 3/7 | Configure SDM file settings | K0 | Yes | Re-configure SDM |
| 3b | Read back SDM to verify | K0 | Yes | Re-configure SDM |
| 4/7 | Install K1 (change key) | K0 | Yes (K0 still factory) | Re-run burn |
| 5/7 | Install K2 (change key) | K0 | Yes (K0 still factory) | Re-run burn |
| 6/7 | Install K3 (change key) | K0 | Yes (K0 still factory) | Re-run burn |
| 6b | Install K4 (change key) | K0 | Yes (K0 still factory) | Re-run burn |
| **7/7** | **Install K0 (master key)** | **K0** | **NO — K0 changes here** | **Must know new K0** |
| Post | Verify with new K0 | New K0 | N/A | If fails: wipe + re-burn |

### Critical Safety Properties of This Sequence

1. **K0 is changed LAST** — until step 7, factory K0 works for recovery
2. **Each step reports card state on failure** — error messages include partial state
3. **Post-burn verification** — authenticates with new K0 and checks SDM active
4. **Auth delay handling** — detected and retried with 1-second delay
5. **NDEF written before SDM enabled** — prevents SDM engine from processing placeholder bytes
6. **Residual SDM cleared first** — prevents conflicts from previous burns

### Failure Window Analysis

The ONLY dangerous window is step 7 (K0 change):
- If K0 change succeeds but card is removed before verification: card has new K0
  but we can't verify. Recovery: try authenticating with derived K0.
- If K0 change partially completes (card removal mid-APDU): card EEPROM may have
  corrupted K0. This is extremely unlikely with contactless cards (the card completes
  the write before responding, or doesn't respond at all).

---

## 5. Wipe APDU Sequence Analysis

The `cmd_wipe` function in `apps/bolty-cli/src/wipe.rs`:

| Step | Operation | Auth | Notes |
|------|-----------|------|-------|
| Pre | Read UID | None | |
| Probe | Try factory K0 auth | K0=factory | Checks if card is already blank |
| Auth | Authenticate with derived K0 | K0=derived | Fails if wrong issuer key |
| 1 | Clear SDM settings | K0=derived | Disable SDM on NDEF file |
| 2 | Write empty NDEF | K0=derived | NLEN=0 |
| 3-6 | Reset K1-K4 to factory | K0=derived | Each key reset individually |
| **7** | **Reset K0 to factory** | **K0=derived** | **K0 changes back to factory** |
| Post | Verify with factory K0 | K0=factory | Confirm successful wipe |

Wipe is the INVERSE of burn. The same safety properties apply: K0 is changed last.

---

## 6. Authentication Delay Deep Dive

### Mechanism
- NTAG424 maintains an internal failed-auth counter
- After repeated failures, card returns `ResponseStatus::AuthenticationDelay`
- Card refuses all subsequent auth attempts until delay expires
- Delay is cleared by: (a) successful auth, (b) "keep trying" — rapid AuthFirst retries within same PCSC connection

### Triggers in bolty-rs
1. **Burn on wrong card**: Factory K0 fails → derived K0 fails = 2 failed auths
2. **Wipe on wrong card**: Factory K0 fails → derived K0 fails = 2 failed auths
3. **Keyver on unknown card**: Derived K0 fails → factory K0 fails = 2 failed auths
4. **Diagnose factory probe**: 1 failed auth if card is provisioned

### Mitigation
- bolty-rs detects auth delay via `is_auth_delay()` / `is_session_auth_delay()`
- When detected, code waits 1 second and retries
- All auth attempts are logged to `/tmp/bolty-audit.log`
- Diagnose command uses non-auth detection (read-only) as primary strategy

### Escalation
The NXP datasheet does not specify exact delay durations or counter thresholds.
From empirical testing and proxmark3 community experience:
- First few failures: ~1 second delay
- Repeated failures: delay escalates (seconds to tens of seconds)
- No permanent lockout observed from auth failures alone
- The counter resets on successful authentication

---

## 7. Card State Detection Recommendations

### Current Strategy (diagnose command)
1. Read UID, GetVersion — safe, identifies chip type
2. GetFileSettings — SDM presence = provisioned
3. Read NDEF — content = provisioned
4. Factory K0 probe — single auth attempt
5. SDM PICC decrypt — local verification

### Recommended Improvements

1. **Pre-burn safety check** (before any write):
   ```
   diagnose --issuer-key <key>
   ```
   Should be run FIRST. Only proceed with burn if state is BLANK or PROVISIONED
   (with matching issuer key). Refuse to burn AUTH_DELAY or INCONSISTENT cards.

2. **Atomic key operations**: Consider batching K1-K4 changes into fewer APDUs
   if the ntag424 crate supports it. Fewer APDUs = fewer failure points.

3. **Transaction logging**: The audit log should record the full APDU sequence
   for every burn/wipe, enabling post-mortem analysis if a card is bricked.

4. **Key verification before K0 change**: After installing K1-K4, verify EACH key
   by authenticating with it before proceeding to K0 change.

5. **Dry-run mode**: Add `--dry-run` flag to burn/wipe that validates all parameters
   and checks card state but does not send any write APDUs.

---

## 8. Safety Checklist for Card Operations

### Before ANY write operation:
- [x] Card UID read and matches expected value *(automatic via `preflight`)*
- [x] Card version confirms NTAG424 DNA *(automatic via `preflight`)*
- [x] Card state detected via auth probe (not AUTH_DELAY — burn/wipe `[0/7]` step catches this) *(automatic)*
- [ ] Correct issuer key for this card UID *(user responsibility — wrong key → auth fails)*
- [x] Audit logging enabled (`/tmp/bolty-audit.log`)

### Before burn:
- [x] Pre-flight check passed *(automatic)*
- [x] State is BLANK or PROVISIONED *(automatic — `[0/7]` step checks card state)*
- [x] SDM URL template is valid *(automatic — URL must contain {picc} and {mac})*
- [x] All 5 keys can be derived from issuer key + UID *(automatic via BoltcardDeterministicDeriver)*
- [ ] Card is on the reader and stable (not being moved) *(user responsibility)*
- [x] Run with `--dry-run` first to preview *(available)*

### Before wipe:
- [x] Pre-flight check passed *(automatic)*
- [x] State is PROVISIONED *(automatic — refuses wipe on BLANK cards)*
- [x] Derived K0 matches card K0 *(automatic — auth fails if wrong key)*
- [x] No authentication delay active *(automatic — AuthRetry "keep trying" clears delay)*
- [x] Run with `--dry-run` first to preview *(available)*

### During burn/wipe:
- [x] Per-key version verified after each K1-K4 change *(automatic)*
- [x] NDEF write verified by readback *(automatic in burn)*
- [x] SDM configuration verified after enable *(automatic in burn)*
- [x] Circuit breaker limits total auth failures *(automatic — 10 failures max)*

### After ANY operation:
- [x] Post-operation verification completed *(automatic: auth with new/old K0)*
- [ ] Audit log reviewed for unexpected APDU responses *(user responsibility)*
- [ ] Card state re-verified with `diagnose` or `keyver` *(user responsibility)*

---

## 9. Known Bricking Scenarios (from community experience)

| Scenario | Cause | Recovery |
|----------|-------|----------|
| Forgot issuer key after burn | K0 changed to unknown derived key | **None** — card permanently locked |
| Interrupted during K0 change | Card removed mid-APDU | Very unlikely (card completes write before responding) |
| Wrong issuer key for wipe | Auth fails, card unchanged | Use correct issuer key |
| Auth delay during burn | Too many failed auths | Wait, then retry |
| SDM offsets wrong | Card scans produce garbage | Reconfigure SDM with correct offsets (needs K0) |
| Access rights lockout | File access set to key Fh (no access) | Requires K0 to reconfigure |

---

## 10. bolty-rs Specific Safety Audit

### Current Safety Strengths
1. ✅ K0 changed last in both burn and wipe
2. ✅ Error messages include partial card state and recovery instructions
3. ✅ Auth delay detected and handled with retry
4. ✅ Post-operation verification in both burn and wipe
5. ✅ Read-only commands (diagnose, picc, inspect, ver, keyver) for safe state detection
6. ✅ All CLI functions generic over `T: Transport` — testable with mock
7. ✅ Audit logging captures all APDU exchanges
8. ✅ NDEF written before SDM enabled (prevents SDM engine corruption)
9. ✅ Residual SDM cleared before re-burn
10. ✅ Pre-flight check: burn/wipe verify card responds + is NTAG424 DNA before any modification APDUs
11. ✅ Per-key version verification: after each K1-K4 change/reset, GetKeyVersion confirms the version was set correctly before proceeding to the next key
12. ✅ Dry-run mode: `--dry-run` flag previews planned actions (derived keys, URL, steps) without sending any APDUs
13. ✅ MockTransport: integration tests cover full burn/wipe/reburn cycle, diagnose, keyver, picc — all hardware-free
14. ✅ Dry-run unit tests verify card state preservation on both factory and provisioned cards

### Remaining Safety Gaps
1. ⚠️ Auth delay escalation not tracked (only 1 retry, may need longer waits)
2. ⚠️ No circuit breaker for repeated auth failures

### Resolved Gaps
- ✅ ~~Mock transport doesn't exist~~ → MockTransport with integration tests
- ✅ ~~No pre-flight diagnose check~~ → `preflight()` verifies NTAG424 DNA before burn/wipe
- ✅ ~~No `--dry-run` mode~~ → `--dry-run` on both burn and wipe (commit `1228bbf`)
- ✅ ~~No per-key verification~~ → GetKeyVersion readback after each K1-K4 change (commit `eec9e5c`)

### Priority Fixes
1. **LOW**: Track auth delay count and escalate wait time
2. **LOW**: Add circuit breaker for repeated auth failures (refuse after N consecutive failures)
