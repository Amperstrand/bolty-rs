# NTAG424 DNA Authentication & Failure Handling

Complete reference for understanding NTAG424 DNA authentication, failure
counters, auth delay, and the circuit breaker pattern needed for safe card
operations.

## 1. Authentication Protocol

NTAG424 DNA uses AES-128 (ISO/IEC 10118-2) in a 3-pass mutual authentication
protocol based on DESFire EV2. The reader proves knowledge of the key without
revealing it.

### 1.1 AuthFirst (command 0x71)

```
Reader → Card:  90 71 00 00 02 [KeyNo] [KeyVer]
```

- `KeyNo` = which key slot (0-4; 0 = master key K0)
- `KeyVer` = key version (0x00 = "use currently active version")

### 1.2 Card Response to AuthFirst

The card checks the **failure counters** BEFORE processing:

| Counter State | Response | Meaning |
|---|---|---|
| SeqFailCtr < 50 | `91 AF` + encrypted RndB (16 bytes) | Challenge accepted — proceed |
| SeqFailCtr ≥ 50 | `91 AD` | Auth delay — card refuses to process |

If the card returns `91AF`, it has generated a random number `RndB`, encrypted
it with the requested key, and sent it to the reader. The reader must now prove
it can decrypt RndB and produce a valid response.

### 1.3 AuthNext (command 0xAF)

```
Reader → Card:  90 AF 00 00 20 [32-byte response]
```

The reader decrypts RndB, generates `RndA`, and sends `RndA || RndB'` (both
rotated and encrypted). The card verifies the response.

### 1.4 Card Response to AuthNext

| Result | SW code | Meaning |
|---|---|---|
| Correct key | `91 00` + encrypted RndA' (16 bytes) | **Success** — session established |
| Wrong key | `91 AE` | **Authentication error** — key doesn't match |

On `91AE` (wrong key):
- **SeqFailCtr** increments by 1
- **TotFailCtr** increments by 1
- After the next `AuthFirst`, if SeqFailCtr ≥ 50, the card returns `91AD`

On `9100` (success):
- **SeqFailCtr** resets to 0
- **TotFailCtr** decreases by `TotFailCtrDecr` (default: 10)

### 1.5 Status Code Summary

| SW1 SW2 | Name | When | Counters Affected |
|---|---|---|---|
| `91 00` | Operation OK | Auth success, or any successful command | SeqFailCtr → 0, TotFailCtr -= 10 |
| `91 AF` | Additional Frame | AuthFirst accepted, waiting for AuthNext | None |
| `91 AE` | Authentication Error | AuthNext with wrong key | SeqFailCtr += 1, TotFailCtr += 1 |
| `91 AD` | Authentication Delay | AuthFirst when SeqFailCtr ≥ 50 | None (blocked before processing) |

## 2. Failure Counter System

NTAG424 maintains three per-key counters. Each key slot (K0-K4) has its own
independent set (verified empirically in T6 — 10 K0 failures do not affect
K1 auth). These are defined in AN12196 §7.4.

### 2.1 The Three Counters

```
┌─────────────────────────────────────────────────────────────┐
│                    Per-Key Counter Set                       │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ SeqFailCtr  │  │ TotFailCtr  │  │ SpentTimeCtr│         │
│  │  (1 byte)   │  │ (2 bytes)   │  │ (2 bytes)   │         │
│  │  Range 0-255│  │ Range 0-1000│  │ Time in FWT │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                  │
│  Trigger: 50             │           Tracks delayed         │
│  → auth delay (91AD)     │           response time          │
│                    Trigger: 1000                             │
│                    → PERMANENT KEY LOCK                      │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Counter Behavior Detail

#### SeqFailCtr — Sequential Failure Counter (1 byte)

Tracks **consecutive** failures since the last successful authentication.

| Event | Action |
|---|---|
| Failed auth (`91AE`) | SeqFailCtr += 1 |
| Successful auth (`9100`) | SeqFailCtr = 0 |
| `Cmd.ChangeKey` | SeqFailCtr = 0 |

**Threshold behavior:**
- **0-49**: Normal operation. AuthFirst returns `91AF` (challenge).
- **50-99**: Auth delay active. AuthFirst returns `91AD`. Delay increases gradually.
- **100-255**: Maximum delay. AuthFirst still returns `91AD`.

**Confirmed volatile (RAM):** Resets when card loses RF power. Verified
empirically in T4 — USB driver unbind/bind (`echo 1-2 | sudo tee
/sys/bus/usb/drivers/usb/unbind && sleep 5 && echo 1-2 | sudo tee
/sys/bus/usb/drivers/usb/bind`) cuts reader antenna and clears auth delay.
Physical card removal also works. PCSC warm reset and pcscd restart do NOT.

#### TotFailCtr — Total Failure Counter (2 bytes)

Tracks **total** failures across the card's lifetime (per key slot).

| Event | Action |
|---|---|
| Failed auth (`91AE`) | TotFailCtr += 1 |
| Successful auth (`9100`) | TotFailCtr -= TotFailCtrDecr (default: 10) |
| `Cmd.ChangeKey` | TotFailCtr = 0 |

**Threshold:**
- `TotFailCtrLimit` (default: **1000**) → **key permanently disabled**
- Once TotFailCtr reaches the limit, the key can **never** be used for
  authentication again. The card is bricked for that key slot.
- Only `Cmd.ChangeKey` can reset TotFailCtr — but ChangeKey requires successful
  K0 auth first. If K0 itself is locked, there is no recovery.

**Non-volatile (EEPROM):** Persists across power cycles. This is why ChangeKey
explicitly resets it — it wouldn't need to if it were volatile.

#### SpentTimeCtr — Spent Time Counter (2 bytes)

Tracks cumulative time spent in delayed responses during auth delay.

| Event | Action |
|---|---|
| Delayed response | SpentTimeCtr += SpentTimeUnit |
| `Cmd.ChangeKey` | SpentTimeCtr = 0 |

`SpentTimeUnit` depends on the Frame Waiting Time (FWT) configuration.

### 2.3 Counter Reset Matrix

| Action | SeqFailCtr | TotFailCtr | SpentTimeCtr |
|---|---|---|---|
| Successful auth | → 0 | -= 10 | unchanged |
| Power cycle (RF field removal) | → 0 (likely) | unchanged | → 0 (likely) |
| `Cmd.ChangeKey` | → 0 | → 0 | → 0 |
| No action (waiting) | unchanged | unchanged | unchanged |

> **Important:** Waiting does NOT decrease any counter. Only successful auth or
> ChangeKey can reduce TotFailCtr. Power cycling only helps with SeqFailCtr.

## 3. Card Lifecycle States

```mermaid
stateDiagram-v2
    [*] --> Factory: Manufacturing

    Factory --> Provisioned: burn()\n(write NDEF, enable SDM,\nchange keys K0-K4)

    Provisioned --> Provisioned: re-burn()\n(auth with current K0,\noverwrite keys)

    Provisioned --> HalfWiped: partial wipe or\nfailed burn mid-operation

    Provisioned --> Factory: wipe()\n(auth with K0,\nreset all keys to zeros)

    HalfWiped --> Factory: wipe() with correct K0\n(may need scan-keys first)

    HalfWiped --> Factory: burn() with factory K0\n(if K0 still factory)

    Factory --> Provisioned: burn()

    Provisioned --> AuthDelay: ≥50 consecutive\nfailed auths (SeqFailCtr)

    AuthDelay --> Provisioned: power cycle +\ncorrect key auth\n(SeqFailCtr resets)

    AuthDelay --> AuthDelay: continued failed auths\n(SeqFailCtr stays ≥50)

    AuthDelay --> PermanentlyLocked: TotFailCtr ≥1000\n(total failures across\nall sessions)

    HalfWiped --> AuthDelay: ≥50 consecutive\nfailed auths

    AuthDelay --> HalfWiped: power cycle +\ncorrect key auth

    PermanentlyLocked --> [*]: key slot permanently\ndisabled — no recovery\nwithout K0 auth

    note right of Factory
        All keys = zeros
        Key version = 0
        SDM disabled
        NDEF empty
    end note

    note right of Provisioned
        K0 = derived key
        K1 = SDM PICC encrypt
        K2 = SDM MAC
        Key version = N
        SDM active
        NDEF has URL template
    end note

    note right of AuthDelay
        Card returns 91AD
        for ALL auth attempts
        SeqFailCtr ≥ 50
        Recovery: power cycle
    end note

    note right of PermanentlyLocked
        TotFailCtr ≥ 1000
        Key CANNOT be used
        Card bricked for that slot
        Read access still works
        (if read = Free)
    end note
```

## 4. Authentication Flow with Failure Paths

```mermaid
flowchart TD
    Start([Reader wants to authenticate]) --> AuthFirst[Send AuthFirst\n90 71 00 00 02 KeyNo KeyVer]

    AuthFirst --> CheckCtrs{Check SeqFailCtr}

    CheckCtrs -->|"≥ 50 (delay active)"| Return91AD[Return 91AD\nAuth Delay]
    CheckCtrs -->|"< 50 (OK)"| GenRndB[Generate RndB\nencrypt with key]
    GenRndB --> Return91AF[Return 91AF + encrypted RndB]

    Return91AF --> ReaderComputes[Reader computes\nresponse using its key]
    ReaderComputes --> AuthNext[Send AuthNext\n90 AF 00 00 20 + 32 bytes]

    AuthNext --> VerifyResp{Card verifies\nreader response}

    VerifyResp -->|"Correct key"| Return9100[Return 9100\nSuccess]
    VerifyResp -->|"Wrong key"| Return91AE[Return 91AE\nAuth Error]

    Return9100 --> ResetSeq[SeqFailCtr = 0\nTotFailCtr -= 10]
    ResetSeq --> SessionEstablished([Session established\ncommands available])

    Return91AE --> IncrSeq[SeqFailCtr += 1\nTotFailCtr += 1]
    IncrSeq --> CheckTotFail{Check TotFailCtr}

    CheckTotFail -->|"≥ 1000"| PermanentLock[⚠️ KEY PERMANENTLY LOCKED\nKey disabled forever\nOnly ChangeKey can reset\nbut requires K0 auth]
    CheckTotFail -->|"< 1000"| ReadyForRetry([Ready for next attempt\nbut SeqFailCtr is climbing])

    Return91AD --> Blocked([Auth blocked\nMust power cycle card\nor wait for ChangeKey])

    style Return91AD fill:#ff9900,color:#000
    style Return91AE fill:#ff6666,color:#fff
    style Return9100 fill:#00cc66,color:#fff
    style PermanentLock fill:#990000,color:#fff
    style SessionEstablished fill:#00cc66,color:#fff
```

## 5. Failure Escalation Timeline

This diagram shows what happens when a bug or user error causes repeated
authentication failures over time:

```mermaid
flowchart LR
    subgraph "Consecutive Failures (SeqFailCtr)"
        F0["Attempt 1\nFail"] --> F1["Attempt 2\nFail"]
        F1 --> F2["Attempt 3-49\nFail"]
        F2 --> F50["Attempt 50\n⚠️ THRESHOLD"]
        F50 --> F51["Attempt 51+\n91AD returned\nimmediately"]
        F51 --> F255["Attempt 255\nMaximum delay"]
    end

    subgraph "Total Failures (TotFailCtr)"
        T0["Total: 0"] --> T1["Total: 1"]
        T1 --> T500["Total: ~500\n(after many sessions)"]
        T500 --> T1000["Total: 1000\n🔒 PERMANENT LOCK"]
    end

    F50 -.->|"Same time axis"| T500

    style F50 fill:#ff9900,color:#000
    style F255 fill:#ff6600,color:#fff
    style T1000 fill:#990000,color:#fff
```

### 5.1 Realistic Failure Rate Examples

| Scenario | Failures/sec | Time to SeqFailCtr=50 | Time to TotFailCtr=1000 |
|---|---|---|---|
| M5StickC polling bug (pre-fix) | 2/sec | **25 seconds** | 8.3 minutes |
| CLI retry loop (3 retries × 2 keys) | 6/session | 8 sessions | 167 sessions |
| E2e test burn→wipe→burn cycle | ~10/session | 5 sessions | 100 sessions |
| Manual user trying different keys | ~1/min | 50 minutes | 16.7 hours |

### 5.2 The Death Spiral

The most dangerous pattern is a **positive feedback loop**:

```
Wrong key → 91AE → retry → 91AE → ... → SeqFailCtr ≥ 50
                                                    ↓
91AD → code interprets as "try again later" → retries with delay
                                                    ↓
Retries still use wrong key → 91AD → TotFailCtr keeps climbing
                                                    ↓
Eventually TotFailCtr ≥ 1000 → KEY PERMANENTLY LOCKED
```

This is exactly what happened to card UID `043365FA967380` — the M5StickC
polling bug spammed failed auths at 2/second, hitting the SeqFailCtr threshold
in 25 seconds, and accumulating TotFailCtr with each session.

## 6. The Circuit Breaker Pattern

### 6.1 Problem

Without a circuit breaker, code can inadvertently brick a card:

1. A bug in key derivation produces the wrong key
2. Each retry attempt increments the failure counters
3. The code retries "helpfully" with delays, making things worse
4. Eventually TotFailCtr reaches 1000 → permanent lock

### 6.2 Solution

A circuit breaker tracks cumulative authentication failures within a single
CLI invocation (or firmware session) and refuses to continue after a threshold.

```mermaid
flowchart TD
    Start([Start operation]) --> Attempt[Attempt authentication]
    Attempt --> Result{Result}

    Result -->|9100 Success| Reset[Failure count = 0]
    Reset --> Proceed([Proceed with operation])

    Result -->|91AE Wrong key| IncrFail[Failure count += 1]
    Result -->|91AD Auth delay| IncrFail

    IncrFail --> CheckThreshold{Failure count ≥ threshold?}

    CheckThreshold -->|"No (< 5)"| Backoff[Wait with backoff\n5s, 15s, 30s]
    Backoff --> Attempt

    CheckThreshold -->|"Yes (≥ 5)"| Abort[ABORT operation\nReport cumulative failures\nWarn about TotFailCtr\nSuggest scan-keys or\npower cycle]
    Abort --> Stop([Stop — do NOT retry])

    style Reset fill:#00cc66,color:#fff
    style Abort fill:#ff6666,color:#fff
    style Stop fill:#990000,color:#fff
```

### 6.3 Implementation Requirements

1. **Track total failures per CLI invocation** (not just per AuthRetry instance)
2. **Threshold**: abort after 5 total failures (conservative — allows
   factory + derived attempts for burn/wipe but prevents runaway loops)
3. **Log to audit**: record each failure with key source and counter estimate
4. **Warn about TotFailCtr**: after 3+ failures, warn that the card's total
   failure counter is accumulating
5. **Suggest alternatives**: recommend `scan-keys` for recovery instead of
   blindly retrying with potentially wrong keys

### 6.4 Current State vs. Needed

| Aspect | Current | Needed for #27 |
|---|---|---|
| Per-operation retry limit | 3 retries per auth sequence | ✓ Adequate |
| Cross-operation tracking | ❌ None — each auth is independent | Track within CLI invocation |
| Cumulative failure logging | ❌ No count across operations | Log to audit |
| TotFailCtr warning | ❌ No warning | Warn after 3+ failures |
| Auth delay detection | ✓ Detects 91AD, aborts | ✓ Adequate |
| Backoff strategy | ✓ 5s/15s/30s | ✓ Adequate |

## 7. How bolty-rs Handles Auth Today

> **Empirically verified (T8):** SDM continues to work during K0 auth delay.
> p=/c= values change on every read, and `mac=true` in diagnose. This is
> because SDM uses K1/K2, which are independent of K0's SeqFailCtr.

### 7.1 AuthRetry (apps/bolty-cli/src/common.rs)

```rust
const AUTH_RETRY_DELAYS: &[u64] = &[5, 15, 30]; // 3 retries
```

Each auth sequence (factory K0, then derived K0) gets its own `AuthRetry`
instance. This means a single `burn` command can trigger up to 6 total auth
attempts (2 sequences × 3 retries each).

### 7.2 Where AuthRetry is used

| Command | Auth sequences | Max total attempts |
|---|---|---|
| `burn` | 2 (factory K0 + derived K0) | 6 |
| `wipe` | 2 (factory K0 + derived K0) | 6 |
| `keyver` | 2 (derived K0 + factory K0) | 6 |
| `inspect` | 1 (optional issuer key) | 3 |
| `diagnose` | 1 (factory K0 probe) | 3 |
| `try-key` | 1 (user-specified key) | 1 (no retry) |
| `scan-keys` | 7 (7 candidates) | 7 (no retry per candidate) |

### 7.3 Risk Assessment

The `scan-keys` command is the safest — it tries 7 different keys with 500ms
pauses between each, and stops immediately on auth delay. Total failures: at
most 7, well below the TotFailCtr danger zone.

The `burn` and `wipe` commands are riskier — up to 6 auth attempts per
invocation. If run in a loop (e.g., e2e test retry), TotFailCtr accumulates
quickly.

## 8. Testing Auth Delay Safely

### 8.1 Simulated Testing (no real card)

Use `MockTransport` to simulate auth responses:

```rust
// Simulate 91AE (wrong key) response
mock.set_auth_response(ResponseStatus::AuthenticationError);

// Simulate 91AD (auth delay) response
mock.set_auth_response(ResponseStatus::AuthenticationDelay);
```

### 8.2 Real Card Testing

**Safe approach:** Use a factory-blank card (factory K0 = zeros) and
deliberately send wrong keys:

1. Start with a blank card (TotFailCtr = 0)
2. Send 1 wrong key → observe 91AE
3. Send 49 more wrong keys → observe transition to 91AD
4. Remove card from reader, wait 2 seconds, replace
5. Send correct key (zeros) → observe 9100 (SeqFailCtr reset)
6. Verify card is still functional

**Never test to TotFailCtr = 1000** — this permanently locks the key.

### 8.3 Verifying Counter Behavior

The NTAG424 does not expose SeqFailCtr or TotFailCtr directly via a read
command. You can only infer the state from behavior:

- `91AF` → SeqFailCtr < 50
- `91AD` → SeqFailCtr ≥ 50
- Permanent auth failure across power cycles → TotFailCtr ≥ 1000

## 9. References

- NXP AN12196 §7.4 — FailedAuthentications Counter feature
- NXP NTAG424 DNA Product Data Sheet Rev. 3.0 §10.5 — AuthenticateEV2First
- NXP NTAG424 DNA Product Data Sheet Rev. 3.0 §10.6.1 — ChangeKey
- `docs/card-safety.md` — Safety reference for card operations
- GitHub issue #27 — Circuit breaker for repeated authentication failures
