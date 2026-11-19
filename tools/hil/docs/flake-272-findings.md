# Flake #272 — root cause, evidence, and fix record (s16 session, 2026-11-17)

> Preserved from the s16 flake-capture session's scratch before cleanup
> (its only copy lived in /tmp — the wrap-up rule now forbids that).
> Part 1: reproduction + root cause. Part 2: the fix (landed as PR #303)
> with the before/after mutex-coverage census. The race-emulator used
> for verification ships alongside as tools/hil/tests/audit_appender.py.

# FINDINGS — issue #272 flake capture (bolty-cli bin suite 93/1)

Session: 2026-11-17, 14:52–15:00 UTC. Repo main @ 39bb080. Agent: flake-capture sub-agent (s16).
**VERDICT: REPRODUCED — 3 distinct failing tests, all audit-content assertions in the bolty-cli bin suite. Most frequent: `audit::security_tests::provenance_tag_is_appended_at_end_of_line`. Root cause is an IN-PROCESS unsynchronized-writer race on the global audit path — NOT the external /tmp/bolty-audit.log appender (disproven as direct cause; it only perturbs scheduling).**

## (a) Static map

Bin suite = **102 tests** (`cargo test -p bolty-cli --bin bolty-cli -- --list`; the "94" in the issue is an older count). Per file: audit 11, bench_lock 3, budget 4, burn 13, diagnose 27, golden_matrix 2, main 15, output 2, provision 8, transport 7, wipe 10.

**Default path /tmp/bolty-audit.log (budget.rs:30 `DEFAULT_LOG`, audit.rs:80-81 fallback):**
- NO bin test reads it. `cmd_budget(None)` (budget.rs:76) is only reached via CLI dispatch (main.rs:421); no test calls it. budget.rs's 4 tests are pure `parse_audit` on fixtures — no I/O.
- Bin tests only WRITE it in the leak window: any `log_event*` while `AUDIT_LOG_PATH == None` (audit.rs:80) → banner + line to the default path. This happens every run (lockless wipe/burn tests logging before/after a mutexed test's set/reset cycle) — confirmed: /tmp/bolty-audit.log grew during test runs.
- External appenders to /tmp/bolty-audit.log therefore **cannot directly flip any bin-test assertion** — the asserting tests read pid-suffixed temp files, not the default path. (External writers to the DEFAULT path: tools/hil/nucula_cycle.py:71 — matches "hardware-lane sessions" as scheduling load, not as writer.)

**The actual shared resource: process-global `AUDIT_LOG_PATH` + one-sided `AUDIT_TEST_MUTEX`.**
Mutex census (actual `.lock()`/`blocking_lock()` sites vs tests in file):
- audit.rs: 11/11 tests mutexed (assert on file content)
- burn.rs: 10/13 mutexed (4 direct + 6 via `setup_audit_isolation!` macro, burn.rs:674-690)
- wipe.rs: **1/10** mutexed (only `wipe_logs_derived_provenance`, wipe.rs:936-937)
- provision.rs: **1/8** mutexed (only `privacy_provision_burns_ctr_only_sdm`, provision.rs:254-255)

Lockless card-op tests (`raw_wipe_*`, `wipe_proceeds_*`, `dry_run_preserves_*`, remaining burn/provision) call `cmd_wipe`/`burn_card`, which emit `log_event_with_provenance` lines (wipe.rs:204-274, burn.rs:237-317) **through the global path**. If a mutexed test has redirected the path to its temp file at that instant, the foreign line lands in that file.

**Writer line formats** (audit.rs `write_raw`/`log_entry`, byte-realistic for the emulator):
- `[{epoch_ms}] SESSION START pid={pid} host={host} exe={exe} wall={RFC3339}Z` (audit.rs:176)
- `[{ts}] EVENT  {msg}` / `... [provenance={Tag}]` (TWO spaces after EVENT; audit.rs:250-251)
- `[{ts}] TX APDU len={n} data={UPPERHEX}` (audit.rs:289)
- `[{ts}] RX OK   sw={91AE} len={n} data={UPPERHEX}` (THREE spaces after OK; audit.rs:300)
- `[{ts}] RX ERR  error=…`, `[{ts}] GET_UID…`, `[{ts}] EVENT  CLOCK_STEP_BACKWARD …`

**Flippable assertions** (all in mutexed audit tests; foreign provenance/glued lines flip them):
1. audit.rs:372-375 — `assert!(!content2.contains("[provenance="), "expected no provenance tag for None, got: {content2:?}")` (test `provenance_tag_emitted`; window = after `remove_file` at :366 through the read)
2. audit.rs:471-474 — `assert!(line.trim_end().ends_with("[provenance=DerivedIssuer(2)]"), "provenance tag must be the trailing token, got: {line:?}")` (test `provenance_tag_is_appended_at_end_of_line`)
3. audit.rs:616-622 — `assert!(structural, "wall clock must be RFC3339 UTC, got: {wall:?}")` (test `session_banner_identifies_writer_exactly_once`; `wall=` token parsed by split, flips when a foreign `[ms]` glues onto it)
4. audit.rs:598-601 `assert_eq!(banners, 1)` and :690/:728 `assert_eq!(marks, 1)` — count assertions, flippable in principle (not observed this session)

## (b) Contention experiment (external appender, BEFORE soak)

Appender: `audit_appender.py` — O_APPEND python3 loop on /tmp/bolty-audit.log, bursts of 2-6 lines every 20-100 ms, formats above (91AE-heavy RX, EVENT incl. `wipe: SUCCESS`, banner once). Backup taken first (see d).

- Bin suite × 8 under appender: **8/8 PASS** (0.11-0.54 s each — tiny exposure window).
- Full workspace × 3 under appender: iter1 PASS (1.27 s), iter2 PASS (0.65 s), **iter3 FAIL (0.19 s)**:
  `test result: FAILED. 101 passed; 1 failed` in `-p bolty-cli --bin bolty-cli` — the 93/1 signature.

Failing block (contention-ws-3.log:110-120):
```
thread 'audit::tests::provenance_tag_emitted' (1112038) panicked at apps/bolty-cli/src/audit.rs:372:9:
expected no provenance tag for None, got: "[1794927387300] EVENT  wipe: p/c pre-verification skipped by explicit flag [provenance=UnknownExternal][1794927387300] EVENT  plain event[1794927387300] EVENT  burn: SUCCESS — K1-K4 + K0 installed (DerivedIssuer(1)) [provenance=DerivedIssuer(1)][1794927387300] EVENT  burn: SUCCESS — K1-K4 + K0 installed (DerivedIssuer(1)) [provenance=DerivedIssuer(1)]\n\n\n\n[1794927387300] EVENT  burn: SUCCESS — K1-K4 + K0 installed (DerivedIssuer(1)) [provenance=DerivedIssuer(1)]\n"
failures:
    audit::tests::provenance_tag_emitted
test result: FAILED. 101 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```
Note: the contaminating lines are from SIBLING TESTS in the same binary (wipe.rs:205, burn.rs:317 texts), NOT from the emulator (it writes only /tmp/bolty-audit.log and cannot touch the pid-suffixed temp file `bolty-audit-test-{pid}-provenance_tag_emitted.log`). The appender's role was scheduling jitter/load — proof below that no appender is needed.

## (c) Clean soak (NO appender)

`BOLTY_SOAK_SLEEP=2 tools/soak-workspace.sh 15 /tmp/opencode/s16-bolty272/soak` → **FLAKE-REPRODUCED: iteration 1 (rc=101)**, TWO tests in one run (`test result: FAILED. 100 passed; 2 failed`, bin suite, soak/run-1.log):

```
thread 'audit::security_tests::provenance_tag_is_appended_at_end_of_line' (1119189) panicked at apps/bolty-cli/src/audit.rs:471:9:
provenance tag must be the trailing token, got: "[1794927498412] EVENT  msg with [brackets] and = signs inside [provenance=DerivedIssuer(2)]\n[1794927498412] EVENT  burn: authenticated with factory K0 [provenance=FactoryDefault]\n"

thread 'audit::issue210_tests::session_banner_identifies_writer_exactly_once' (1119183) panicked at apps/bolty-cli/src/audit.rs:622:9:
wall clock must be RFC3339 UTC, got: "2026-11-17T14:58:18.414Z[1794927498414]"
```

Frequency loop (15 further clean workspace iterations): **2/15 failed (~13%)**, both `provenance_tag_is_appended_at_end_of_line`; iter7 block (freq-7.log) shows the glued-line signature — foreign payload inserted between the victim's payload-write and its newline-write: `...[provenance=DerivedIssuer(2)][1794927533367] EVENT  burn: authenticated with factory K0 [provenance=FactoryDefault]\n\n`.

Totals this session: 4 failure events / ~27 workspace-equivalent iterations; 3 distinct victim tests; contaminators always lockless burn/wipe writers (`burn: authenticated with factory K0 [provenance=FactoryDefault]` burn.rs:238, `burn: SUCCESS — … (DerivedIssuer(1))` burn.rs:317, `wipe: p/c pre-verification skipped… [provenance=UnknownExternal]` wipe.rs:205).

**Mechanism (why the external-writer theory felt right but isn't the direct cause):**
1. `AUDIT_LOG_PATH` is a process-global; mutexed audit tests point it at their own temp file for their duration.
2. Lockless wipe/burn/provision tests log provenance-tagged lines through the same global concurrently.
3. `write_raw` (audit.rs:194-204) does `writeln!` on an UNBUFFERED `File` ⇒ TWO write() syscalls per line (payload, then `\n`); concurrent O_APPEND writers interleave mid-line → glued same-line entries (matches issue #256 lore and the observed `\n\n\n\n` runs).
4. Foreign `[provenance=…]` tokens/glued `[ms]` then flip the `!contains` / `ends_with` / wall-structural assertions (above).
5. Rarity: needs sub-ms overlap inside a 0.02 s suite; probability rises with thread-count/load — explaining both real sightings on busy hardware-lane boxes and the emulator-load coincidence. External appenders to /tmp/bolty-audit.log add jitter (and real bench processes also append there via nucula_cycle.py), which is why #276's suspicion correlated with hardware lanes.

Fix directions (for the owning session, not applied): single `write_all` of payload+`\n` (kills gluing), plus either a writer-side mutex shared by ALL audit-writing code paths (not just asserting tests) or `serial_test` on the audit-path-mutating group.

## (d) Restore confirmation

- Pre-experiment: /tmp/bolty-audit.log existed — 314049 bytes, mtime 2026-11-14 14:20:43 +0100, mode 600 (possible bench evidence). Backed up byte-exact: `audit-backup-1794927133.log` (`cp -a`).
- Appender killed after experiments (verified dead, no stray procs).
- FINAL RESTORE: backup copied back over /tmp/bolty-audit.log; `diff -q` clean; size 314049, mode 600. **State = pre-session exact.** (The file legitimately received test leak-window + emulator lines during runs; all were reverted by the restore.)

## (e) Verdict

**REPRODUCED — failing tests: `audit::security_tests::provenance_tag_is_appended_at_end_of_line` (audit.rs:471, 3 of 4 events), `audit::tests::provenance_tag_emitted` (audit.rs:372), `audit::issue210_tests::session_banner_identifies_writer_exactly_once` (audit.rs:622); in-process unsynchronized audit-writer race via the global `AUDIT_LOG_PATH`, not the external /tmp/bolty-audit.log appender.**

Artifacts: contention-run-{1..8}.log, contention-ws-{1..3}.log, soak/run-1.log, freq-{1..15}.log, build.log, audit_appender.py, appender.out, audit-backup-1794927133.log.
# FINDINGS-2 — fix implementation for issue #272 (follows FINDINGS.md)

Session: 2026-11-17, 15:04–15:12 UTC. Branch `fix/audit-write-race-272`
off main @ 39bb080, one commit: **3d529f9** (`fix(cli): one-write audit
lines + full AUDIT_TEST_MUTEX coverage in the bin suite (#272)`).

## Diff summary

3 files, +49/−25:

- `apps/bolty-cli/src/audit.rs` (+34/−1)
  - `write_raw` (audit.rs:194 → now ~:226): payload + `'\n'` built into one
    `format!` and emitted with a single `f.write_all(...)` instead of
    `writeln!` on the unbuffered File. Output bytes identical — only
    syscall grouping changes (payload+\n were two write()s, now one).
    Comment records the rationale (#256 lore / #272 test writers).
    Checked all other `write_raw` callers (`write_session_banner`,
    `log_entry`, the CLOCK_STEP note in `timestamp`): all single-line
    writes, same bytes, no behavior change.
  - `setup_audit_isolation!` macro generalized here (module level,
    `#[cfg(test)]`, re-exported `pub(crate) use`): the burn.rs-local
    macro moved up and made crate-shared via `$crate::` paths. Temp-file
    prefix renamed `bolty-security-burn-…` → `bolty-audit-isolated-…`
    since it is no longer burn-specific.
- `apps/bolty-cli/src/burn.rs` (+3/−22): local macro deleted,
  `use crate::audit::setup_audit_isolation;` imported in
  `mod security_tests`; the 6 existing `setup_audit_isolation!()` call
  sites are byte-identical. No test bodies touched.
- `apps/bolty-cli/src/wipe.rs` (+10/−0): 1 import line + one
  `let (_guard, _path) = setup_audit_isolation!();` first line in each
  of the 9 previously-lockless tests. No assertion or body changes.

## Mutex-coverage census AFTER the change (wrapped/total per bin-suite file)

| file | before | after | note |
|---|---|---|---|
| audit.rs | 11/11 | 11/11 | unchanged (direct/manual pattern) |
| burn.rs | 10/13 | 10/13 | 3 lockless left unwrapped — see judgment calls |
| wipe.rs | 1/10 | **10/10** | +9 via shared macro |
| provision.rs | 1/8 | 1/8 | 7 lockless left unwrapped — see judgment calls |
| diagnose.rs (27), main.rs (15), transport.rs (7), budget.rs (4), bench_lock.rs (3), output.rs (2), golden_matrix_tests.rs (2) | 0 | 0 | no test writes audit lines (verified: no `audit::`/`log_event` refs and no transitively-writing calls — diagnose's `json_includes_provenance` drives `cmd_diagnose`, which never logs; golden_matrix drives `MockTransport::transmit` directly; MockTransport and the `bolty-ntag` library have zero audit-module references) |

Every audit-WRITING test in the bin suite now holds `AUDIT_TEST_MUTEX`
(31 tests total: 11 audit + 10 burn + 10 wipe + …+ provision's 1 → 32
counting provision). No double-lock nesting exists: `AUDIT_TEST_MUTEX`
is acquired only in test code; `cmd_burn`/`cmd_wipe`/`burn_card` never
take it, so wrapped tests cannot self-deadlock. The macro holds a tokio
guard across `.await` (documented await-safe, same semantics as before).

## Judgment calls — tests left unwrapped, and why

- **burn.rs 3 lockless** (`dry_run_preserves_factory_card_state`,
  `confirm_uid_rejects_mismatch`, `confirm_uid_accepts_match`):
  provably never write an audit line. The dry-run tests return at
  burn_card's dry-run branch (burn.rs:117-145) and the UID-mismatch test
  bails at burn.rs:97-106 — both BEFORE the first
  `audit::log_event_with_provenance` call (burn.rs:237). No other code
  on those paths logs (MockTransport and `bolty-ntag` contain no audit
  references; the library cannot reach the bin crate's audit module).
  Per the "don't blanket-wrap for symmetry" rule they stay bare.
- **provision.rs 7 lockless**: pure `parse_provision_response` fixture
  tests — no transport, no I/O, no logging. Unwrapped.
- The observed contaminator lines in FINDINGS.md (`burn: authenticated
  with factory K0`, `burn: SUCCESS — … (DerivedIssuer(1))`,
  `wipe: p/c pre-verification skipped…`) all originate from the wipe
  tests' setup burns and wipe paths (wipe.rs helpers always burn with
  `dry_run: false`) — i.e. exactly the 9 tests now wrapped; none come
  from the 3 unwrapped burn tests, consistent with the analysis.

## Verification (exact numbers)

a. `cargo test -p bolty-cli --bin bolty-cli`: **102 passed; 0 failed**
   (0 ignored, 0 filtered out).
b. Frequency loop: **20/20 iterations PASS** of
   `cargo test --workspace --exclude bolty-esp32` (logs:
   `verify-fix-{1..20}.log`, each contains the bin suite `102 passed`).
   Pre-fix baseline was ~13%/iteration failure (4 events in the capture
   session). 0 failures post-fix; nothing to analyze.
c. `cargo clippy -p bolty-cli --all-targets -- -D warnings`: clean
   (finished, no warnings). `cargo fmt --all --check`: clean (after
   rustfmt reordered the new `use` line in wipe.rs — applied via
   `cargo fmt`, the only formatter touch).

## Operational notes

- No push, no `gh`, no hardware, `/tmp/bolty-audit.log` untouched
  (verify-fix logs show test writes now land in the wrapped tests' own
  `bolty-audit-isolated-*` temp files under the mutex, not in the
  default path during a victim's window).
- Untracked flake-capture artifacts (FINDINGS.md, appender.out,
  audit_appender.py) deliberately left out of the commit.
- One `cargo fmt` fix-up mid-verify (import ordering) — the only
  deviation from the first-pass diff; re-checked clean afterwards.
