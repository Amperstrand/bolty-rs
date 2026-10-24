# Card-write retry budgets — per card class

Task 6 of [issue #92](https://github.com/Amberstrand/bolty-rs/issues/92):
the documented budget E2E OTC work (#56) depends on. Source of truth:
`apps/bolty-cli/src/common.rs` (`AUTH_RETRY_DELAYS`, `AuthRetry`,
circuit breaker) and the call sites in `burn.rs` / `wipe.rs`.

## Budget table

| Card class | Write path | Auth budget | Delays | Notes |
|---|---|---|---|---|
| **Blank / factory** (factory K0 authenticates) | burn | 1st attempt normally succeeds | — | Detected by the factory-K0 probe (TSX substitutes `GetKeyVersion(K1) != "00"`); reported as "Card is BLANK (factory keys)" |
| **Provisioned / re-burn** (provided K0) | burn | up to **11 auth attempts** (1 + `AUTH_RETRY_DELAYS`' 10 entries) per auth site | **all zero-second** | The card is auth-delayed, not wrong-key: per the NTAG424 datasheet the correct strategy is *keep trying until the full delay is spent* — AuthFirst repeatedly within the SAME connection. The budget is attempt-count, not wall-clock |
| **Auth-delayed** (any correct-key path hitting the delay) | burn (factory, provided-K0, and derive-keys sites — three independent `AuthRetry` instances) | 11 attempts per site | zero-second retries | On exhaustion: explicit message directing to `scan-keys` (wrong-key hypothesis) rather than silent failure |
| **Auth-delayed** (wipe's K0 auth) | wipe | 11 attempts (`AuthRetry` at `wipe.rs:197+`, same `AUTH_RETRY_DELAYS` table as burn) | zero-second retries | True-up for #149: the K0 authentication on the derived/raw-key path IS auth-delay-backed; the process-wide circuit breaker applies as everywhere |
| **Any** (already-wiped probe) | wipe (factory-K0 detection, `wipe.rs:138`) | **single attempt, no retry** | — | The already-wiped detection probe is deliberately budget-free; anything else surfaces directly or flows into the K0 auth row above |
| **Wrong key** | burn | bounded by the **circuit breaker**: 10 total auth failures per process (`CIRCUIT_BREAKER_THRESHOLD`, process-wide atomic) | — | Prevents hammering a card with wrong keys; the breaker fires before per-site budgets could stack |

## Interpretation rules for E2E OTC (#56)

- A successful burn on a healthy card of either class must complete within
  **≤ 11 auth attempts per site, 0 s scheduled delay** — any test observing
  more than that is a regression against this budget.
- The circuit breaker is the global backstop: **no test may drive the
  process past 10 total auth failures** expecting success; past that the
  correct behavior is the breaker's refusal.
- Wipe's ALREADY-WIPED probe is deliberately budget-free (one probe,
  no retry); its K0 authentication on the key-bearing paths carries
  the standard auth-delay `AuthRetry` budget above (the code at
  `wipe.rs:197+` predates this doc's earlier "no retry" claim — this
  row is the #149 true-up). Tests must not
  loop wipe on auth-delay errors.
- The zero-delay table is a deliberate choice (same-connection AuthFirst
  repeats spend the card's internal delay), not an omission: changing any
  entry to a sleep would change burn wall-clock behavior E2E tests observe.

Firmware-side note: the ESP32 console path has **no retry machinery** —
`burn`/`wipe` over serial surface `AuthDelay` as a display/serial failure
("Remove card from reader field for several seconds and retry") and leave
retrying to the operator; the budgets above are the host-CLI contract.
