# NTAG424 Empirical Test Plan

Systematic hardware verification of every claim in `docs/ntag424-auth.md`.
Each test verifies a specific hypothesis. Tests are categorized by danger level.

## Test Results Summary (2026-06-16)

| Test | Status | Result |
|---|---|---|
| T1 | ✅ PASS | Factory auth works, card BLANK |
| T2 | ✅ PASS | Wrong key → 91AE, recovery with correct key → 9100 |
| T3 | ✅ PASS | **Threshold is EXACTLY 50** (attempts 1-50 = 91AE, 51+ = 91AD) |
| T4 | ✅ PASS | **SeqFailCtr IS volatile** — USB driver unbind/bind clears auth delay |
| T5 | ✅ N/A | Cannot definitively test without approaching permanent lock (1000) |
| T6 | ✅ PASS | **Per-key counters ARE independent** — 10 K0 failures don't block K1 |
| T7 | ✅ PASS | Free read works during delay (diagnose returns full card info) |
| T8 | ✅ PASS | **SDM works during auth delay** — p=/c= change every read, mac=true |
| T9-T12 | ⏸ SKIP | Lower priority, depend on extended failure accumulation |
| T13 | 🚫 DO NOT RUN | Permanent lock — irreversible |
| T14 | ⏸ SKIP | GetKeySettings byte layout — lower priority |
| T15 | ✅ PASS | Warm reset does NOT clear delay (PCSC reconnect keeps card powered) |

### Key Empirical Findings (Corrected 2026-06-16)

1. **SeqFailCtr threshold is EXACTLY 50** — attempt 50 returns 91AE (processed),
   attempt 51 returns 91AD (blocked). No variance.

2. **SeqFailCtr is NON-VOLATILE (EEPROM)** — persists across ALL power cycling
   methods tested: PCSC reconnect, pcscd restart, SCARD_UNPOWER_CARD
   (reconnect and disconnect+connect), USB driver unbind/bind, USB root hub
   power cycle. Physical card removal has NOT been verified but the spec
   strongly implies it would also NOT clear SeqFailCtr.

3. **Auth delay recovery: "Keep trying" within a single PCSC connection.**
   The NT4H2421Gx product data sheet states: *"AUTHENTICATION_DELAY ADh:
   Currently not allowed to authenticate. Keep trying until full delay is
   spent."* Empirically verified: 2-5 rapid AuthFirst commands within a SINGLE
   PCSC connection clears the delay. Each new PCSC connection RESETS the delay
   state, so retrying via new connections does NOT work.

4. **T4 was misattributed.** The original T4 "success" from USB driver unbind
   was actually caused by the pyscard script sending AuthFirst within a single
   connection before the bolty-cli test. The USB unbind was coincidental.

5. **Per-key counters ARE independent** — 10 failed K0 auths do not affect
   K1 auth. K1 still returns 91AE (processed) when K0's SeqFailCtr = 10.

6. **SDM works during K0 auth delay** — SDM uses K1 (PICC encrypt) and K2
   (MAC), which are independent of K0. During auth delay:
   - p=/c= values change on every read ✅
   - Diagnose shows `mac=true` ✅
   - Card state correctly shows PROVISIONED ✅
   - A card in auth delay can still process payments but can't be re-keyed.

7. **Free read works during auth delay** — diagnose successfully reads UID,
   version, file settings, and NDEF content. Only K0 authentication is blocked.

8. **SCARD_UNPOWER_CARD does not cut RF on ACS ACR1252.** Both
   `SCardReconnect(UnpowerCard)` and `SCardDisconnect(UnpowerCard) +
   SCardConnect()` return success but do not interrupt the RF field.

## Safety Classification

| Level | Symbol | Description |
|---|---|---|
| **SAFE** | 🟢 | Cannot damage card. Read-only or reversible. |
| **CAUTION** | 🟡 | Uses auth failure budget. Recoverable with correct key. |
| **DANGEROUS** | 🔴 | Approaches TotFailCtr limit. May permanently lock a key. Use sacrificial card only. |

## Prerequisites

- Factory-blank NTAG424 DNA card (all keys = zeros, version = 0)
- PCSC reader (ACS ACR1252 or similar)
- bolty-cli built and available on PATH
- A log file to record results: `touch /tmp/ntag-test-log.txt`

## Test Execution Rules

1. Always start from a known card state (verify with `diagnose`)
2. Record the result after each test step
3. If a test produces an unexpected result, STOP and investigate
4. Between CAUTION tests, verify card is still recoverable
5. Never run DANGEROUS tests on a card you need

---

## T1: AuthFirst on factory card returns 91AF 🟢

**Hypothesis:** A factory card (K0 = zeros) accepts AuthFirst with key version 0
and returns 91AF (challenge).

**Procedure:**
```bash
bolty-cli diagnose --issuer-key 00000000000000000000000000000001
```
- Card should be BLANK, factory K0 = OK

**Expected:** `Card state: BLANK`, `Factory K0: OK`
**Verifies:** Factory auth works, card is in known state

---

## T2: Single wrong key returns 91AE 🟢

**Hypothesis:** AuthNext with wrong key returns 91AE, and the card remains
responsive for subsequent auth attempts.

**Procedure:**
```bash
# Try a wrong key (all 0xFF) against K0
bolty-cli try-key --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF --key-no 0
```

**Expected:** `❌ Key rejected (wrong key)`
**Post-state:** Card should still be fully functional (SeqFailCtr = 1)
**Verify recovery:**
```bash
bolty-cli try-key --key 00000000000000000000000000000000 --key-no 0
```
**Expected:** `✅ Key accepted!`

---

## T3: SeqFailCtr threshold — exactly 50 failures triggers 91AD 🟡

**Hypothesis:** The card starts returning 91AD after exactly 50 consecutive
failed auth attempts (not 49, not 51).

**Procedure:**
This requires sending exactly 50 AuthFirst+AuthNext pairs with a wrong key.
Use a script that tries the wrong key repeatedly and counts responses:

```bash
# Run 55 wrong-key attempts, recording each result
for i in $(seq 1 55); do
  echo -n "Attempt $i: " >> /tmp/ntag-test-log.txt
  bolty-cli try-key --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF --key-no 0 2>&1 | \
    grep -oE '✅|❌|⚠️' >> /tmp/ntag-test-log.txt
  sleep 0.3
done
cat /tmp/ntag-test-log.txt
```

**Expected:**
- Attempts 1-49: `❌` (91AE — wrong key, auth processed)
- Attempt 50: transition point — observe carefully
- Attempts 51-55: `⚠️` (91AD — auth delay)

**Key question:** Is the threshold exactly at 50, or is there variance?

**Recovery (REQUIRED after test):**
```bash
# Power cycle: remove card, wait 2 seconds, replace
# Then authenticate with correct key
bolty-cli try-key --key 00000000000000000000000000000000 --key-no 0
```
**Expected:** `✅ Key accepted!` (SeqFailCtr reset to 0)

---

## T4: SeqFailCtr is volatile — power cycle resets it 🟡

**Hypothesis:** Physically removing the card from the RF field resets SeqFailCtr
to 0, clearing the auth delay.

**Prerequisite:** T3 must have pushed SeqFailCtr ≥ 50 (card in auth delay).

**Procedure:**
1. Verify card is in auth delay:
   ```bash
   bolty-cli try-key --key 00000000000000000000000000000000 --key-no 0
   # Expected: ⚠️ auth delay (91AD)
   ```
2. **Remove card from reader.** Wait 2 seconds.
3. **Place card back on reader.**
4. Immediately try correct key:
   ```bash
   bolty-cli try-key --key 00000000000000000000000000000000 --key-no 0
   ```

**Expected outcomes:**
- If SeqFailCtr is volatile: `✅ Key accepted!` (delay cleared)
- If SeqFailCtr is non-volatile: `⚠️ Auth delay active` (delay persists)

**This is the most important test** — it determines whether physical card
removal is a valid recovery strategy.

---

## T5: TotFailCtr persists across power cycles 🟡

**Hypothesis:** TotFailCtr accumulates across power cycles (non-volatile).
After T3+T4, the card has ~50 total failures on K0 that were NOT reset by
power cycling.

**Procedure:**
1. After T4 recovery, burn the card:
   ```bash
   bolty-cli burn --issuer-key 00000000000000000000000000000001 \
     --url 'https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c=[[{mac}' --version 1
   ```
2. Wipe the card (this calls ChangeKey, which should reset TotFailCtr):
   ```bash
   bolty-cli wipe --issuer-key 00000000000000000000000000000001 --version 1
   ```
3. Repeat T3 again (50 more wrong-key attempts)

**Key question:** Does the second round of T3 behave the same as the first?
If TotFailCtr persisted (didn't reset via ChangeKey during wipe), the card
might enter permanent lock sooner.

**Note:** This test only works if ChangeKey does NOT reset TotFailCtr. If it
does, TotFailCtr is back to 0 after wipe and this test is a no-op.

---

## T6: Per-key counter independence 🟡

**Hypothesis:** K0 and K1 have independent SeqFailCtr counters. Failing K0
auth does not affect K1 auth.

**Procedure:**
1. Start with factory card
2. Burn the card (installs K0-K4):
   ```bash
   bolty-cli burn --issuer-key 00000000000000000000000000000001 \
     --url 'https://boltcardpoc.psbt.me/?p={picc:uid+ctr}&c=[[{mac}' --version 1
   ```
3. Send 10 wrong-key attempts against K0:
   ```bash
   for i in $(seq 1 10); do
     bolty-cli try-key --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF --key-no 0
     sleep 0.3
   done
   ```
4. Try wrong key against K1:
   ```bash
   bolty-cli try-key --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF --key-no 1
   ```
5. Try correct K0:
   ```bash
   bolty-cli try-key --key $(bolty-cli derive-keys --issuer-key \
     00000000000000000000000000000001 --uid <UID> --version 1 --verbose | \
     grep K0 | awk '{print $2}') --key-no 0
   ```

**Expected:**
- Step 4: `❌` (wrong K1 key — K1 SeqFailCtr was 0, processes the attempt)
- Step 5: `✅` (correct K0 — K0 SeqFailCtr resets to 0)

**Key question:** Does K0's SeqFailCtr=10 affect K1's SeqFailCtr?

---

## T7: Free read works during auth delay 🟡

**Hypothesis:** NDEF read (free access) still works when K0 is in auth delay.

**Prerequisite:** Push K0 into auth delay (run T3 first).

**Procedure:**
1. After T3, verify K0 is in auth delay:
   ```bash
   bolty-cli try-key --key 00000000000000000000000000000000
   # Expected: ⚠️ auth delay
   ```
2. Read NDEF (no auth required):
   ```bash
   bolty-cli url
   ```
3. Diagnose (reads file settings without K0 auth):
   ```bash
   bolty-cli diagnose --issuer-key 00000000000000000000000000000001
   ```

**Expected:**
- Step 2: NDEF URL is returned (free read unaffected by auth delay)
- Step 3: Diagnose shows SDM settings, NDEF content, but K0 auth = delay

**Key question:** Is the card fully readable during auth delay, or are some
operations blocked?

---

## T8: SDM still generates valid MACs during auth delay 🟡

**Hypothesis:** SDM continues to dynamically replace `p=` and `c=` in the NDEF
URL even when K0 is in auth delay. SDM uses K1/K2, not K0.

**Prerequisite:** Card must be provisioned (burned) AND K0 in auth delay.

**Procedure:**
1. Burn card
2. Verify SDM works (diagnose shows `mac=true`)
3. Push K0 into auth delay (T3)
4. Read URL multiple times:
   ```bash
   bolty-cli url
   bolty-cli url
   bolty-cli url
   ```
5. Check if p= and c= values change between reads

**Expected:** Each read produces different p= and c= values (SDM active)
**Key question:** Does K0 auth delay affect SDM (K1/K2) operation?

---

## T9: Auth delay escalation — does delay increase? 🟡

**Hypothesis:** Between SeqFailCtr 50-255, the auth delay gradually increases.
At 50, the card might still respond quickly with 91AD. At 200+, the response
is significantly delayed.

**Procedure:**
This is hard to measure with bolty-cli (APDU response time includes PCSC
overhead). Instead, check the audit log timestamps:

1. Clear audit log: `rm /tmp/bolty-audit.log`
2. Send 200 wrong-key attempts with timing:
   ```bash
   for i in $(seq 1 200); do
     start=$(date +%s%N)
     bolty-cli try-key --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 2>/dev/null
     end=$(date +%s%N)
     elapsed=$(( (end - start) / 1000000 ))
     echo "Attempt $i: ${elapsed}ms" >> /tmp/ntag-test-log.txt
   done
   ```
3. Plot the response times

**Expected:**
- Attempts 1-49: ~50ms (fast rejection)
- Attempts 50-100: gradually increasing delay
- Attempts 100+: longer delay or immediate 91AD

**Key question:** Does the card actually delay its response, or does it
immediately return 91AD regardless of SeqFailCtr value?

---

## T10: Successful auth resets SeqFailCtr to 0 🟡

**Hypothesis:** After a successful K0 auth, SeqFailCtr resets to 0. The next
49 wrong-key attempts will work normally before auth delay triggers again.

**Procedure:**
1. Send 30 wrong-key attempts (SeqFailCtr = 30)
2. Auth with correct key (SeqFailCtr → 0)
3. Send 49 wrong-key attempts (should all return 91AE, not 91AD)
4. Send 1 more (attempt 50 — should trigger 91AD)

**Expected:** 91AD triggers at attempt 50 after the reset, confirming
SeqFailCtr was properly reset to 0 by the successful auth.

---

## T11: TotFailCtr decrease on successful auth 🟡

**Hypothesis:** TotFailCtr decreases by 10 (TotFailCtrDecr) on each successful
auth. This means after 30 failures + 1 success, TotFailCtr = 20 (not 0).

**Procedure:**
1. Note: TotFailCtr is NOT directly readable. We can only infer it.
2. Strategy: accumulate failures across multiple sessions and observe when
   permanent lock approaches.
3. This is a LONG-RUNNING test — repeat T3 + recovery 20 times:
   - Session 1: 50 failures → TotFailCtr ≈ 50
   - Recovery: 1 success → TotFailCtr ≈ 40 (50 - 10)
   - Session 2: 50 failures → TotFailCtr ≈ 90
   - Recovery: 1 success → TotFailCtr ≈ 80
   - ... continue for 20 sessions
   - Expected TotFailCtr after 20 cycles: ~20 × (50-10) = ~800

**Key question:** Does TotFailCtr actually decrease by 10 per success?

**⚠️ Warning:** After ~25 cycles, TotFailCtr approaches 1000. Stop at cycle 20
to stay safe (TotFailCtr ≈ 800, leaving 200 failure budget).

---

## T12: ChangeKey resets all counters 🔴 DANGEROUS

**Hypothesis:** `Cmd.ChangeKey` resets SeqFailCtr, TotFailCtr, and SpentTimeCtr
to 0. After ChangeKey, the full 1000-failure budget is restored.

**Procedure:**
1. Accumulate ~200 TotFailCtr (4 rounds of T3)
2. Wipe the card (triggers ChangeKey for K0-K4):
   ```bash
   bolty-cli wipe --issuer-key 00000000000000000000000000000001 --version 1
   ```
3. Run T3 again (50 wrong-key attempts)
4. Run T3 AGAIN (50 more wrong-key attempts)

**Expected:** If ChangeKey reset TotFailCtr, the card should handle 100 total
failures without issue (both rounds of T3 complete successfully).
If ChangeKey did NOT reset TotFailCtr, the second round might fail earlier
or the card might behave differently.

**Danger:** This test uses 200+ failures. Must verify TotFailCtr was reset
before running more tests.

---

## T13: Permanent lock at TotFailCtr = 1000 — DO NOT RUN 🔴

**NEVER RUN THIS TEST. This will permanently and irreversibly brick the card.**

The AN12196 spec states: "when TotFailCtrLimit is reached, related key cannot
be used for Authentication anymore." ChangeKey (the only counter reset) requires
K0 auth, creating a circular dependency with no recovery:

- K0 TotFailCtr ≥ 1000 → K0 cannot authenticate
- K0 cannot authenticate → Cannot run ChangeKey
- Cannot run ChangeKey → Cannot reset TotFailCtr
- **Card permanently bricked for all key management**

The card can still be read (NDEF free read), but can never be burned, wiped,
or re-keyed. It is permanently read-only.

This test is documented for completeness only. The behavior is confirmed by
the spec — no empirical verification is worth sacrificing a card.

---

## T14: GetKeySettings response interpretation 🟢

**Hypothesis:** The GetKeySettings response contains key version information
that can be used to determine the card's key state without authentication.

**Procedure:**
```bash
# Capture raw GetKeySettings via audit log
rm /tmp/bolty-audit.log
bolty-cli diagnose --issuer-key 00000000000000000000000000000001
grep '90F5\|F500' /tmp/bolty-audit.log
```

**Document the byte layout** of the response. Which bytes are key versions?
Which byte is the app master key version?

---

## T15: PCSC warm reset vs cold reset 🟢

**Hypothesis:** PCSC's `SCardReconnect` with `SCARD_RESET_CARD` performs a warm
reset (does NOT power-cycle the card). Only physical removal does a cold reset.

**Procedure:**
1. Push card into auth delay (T3)
2. Run `bolty-cli try-key --key 00000000000000000000000000000000`
   - This creates a new PCSC connection (warm reset)
3. Observe: does auth delay clear?
4. Physically remove and replace card
5. Run same command again
6. Observe: does auth delay clear now?

**Expected:**
- Step 3: still 91AD (warm reset doesn't clear SeqFailCtr)
- Step 5: 9100 success (cold reset clears SeqFailCtr)

---

## Test Result Recording Template

After running each test, fill in:

```
## T<N> Result
- Date: 
- Card UID: 
- Starting state: 
- Steps executed: 
- Actual result: 
- Matches hypothesis: YES / NO / PARTIAL
- Notes: 
- Card state after test: 
```

---

## Summary: Known Unknowns to Resolve

| # | Question | Test | Priority |
|---|---|---|---|
| 1 | Does power cycle reset SeqFailCtr? | T4 | **Critical** |
| 2 | Is the threshold exactly 50? | T3 | High |
| 3 | Does delay actually increase 50-255? | T9 | Medium |
| 4 | Are K0/K1 counters independent? | T6 | High |
| 5 | Does free read work during delay? | T7 | High |
| 6 | Does SDM work during delay? | T8 | High |
| 7 | Does TotFailCtr decrease by 10? | T11 | Medium |
| 8 | Does ChangeKey reset all counters? | T12 | Medium |
| 9 | Does warm reset ≠ cold reset? | T15 | High |
| 10 | What's in GetKeySettings bytes? | T14 | Medium |
| 11 | Does permanent lock happen at 1000? | T13 | ~~Low~~ **DO NOT RUN** — spec confirms irreversible |
