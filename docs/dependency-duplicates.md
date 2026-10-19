# Dependency duplicate triage (issue #110, 2026-10-19)

Baseline: `cargo tree --workspace -e normal --duplicates` at main `38120e6`
= 9 duplicate bases. Decisions below, each backed by `cargo tree --invert`
evidence captured the same day. This is a decision record, not a to-do —
re-triage when a listed owner issue closes.

| Base | Versions | Root (invert evidence) | Decision | Owner |
|---|---|---|---|---|
| digest | 0.10.7 / 0.11.2 | 0.10: ntag424 fork → p224 0.13 → ecdsa 0.16. 0.11: bolty-core → cmac 0.8 | **defer** — collapses only via the ntag424 source decision (fork refresh vs upstream re-pin) | #109 |
| block-buffer | 0.10.4 / 0.12.0 | rides digest 0.10 / 0.11 | **defer** — collapses with digest | #109 |
| crypto-common | 0.1.6 / 0.2.1 | rides digest 0.10 / 0.11 | **defer** — collapses with digest | #109 |
| cpufeatures | 0.2.17 / 0.3.0 | rides digest 0.10 / 0.11 | **defer** — collapses with digest | #109 |
| getrandom | 0.2.17 / 0.3.4 | rides digest/rand-core 0.6 / 0.10 | **defer** — collapses with digest | #109 |
| heapless | 0.8.0 / 0.9.2 | 0.8: mfrc522 fork @ e9ced1e (+ pn7160-nci @ f2a250b per ccid-firmware-rs). 0.9: bolty-core | **defer** — 0.8 is pinned by the mfrc522 fork; feed/retire first | #108 (+ ccid-firmware-rs#142) |
| syn | 2.0.117 / 3.0.4 | 2: clap_derive/darling/enumset_derive (bolty-cli). 3: displaydoc → icu → idna → url → ureq (bolty-cli) | **accept** — proc-macro generational split, host build-time only, never in firmware graphs | — |
| webpki-roots | 0.26.11 / 1.0.9 | ureq 2.12.1 → webpki-roots 0.26.11 → webpki-roots 1.0.9 (the 0.x crate wraps the 1.x crate) | **accept** — entirely ureq's packaging choice; collapsing needs a ureq major bump, host CLI only | — |

Notes:

- The digest family (digest + 5 riders) is one decision, not six — all six
  flip together when the ntag424 fork's P-224 chain moves to digest 0.11
  (or the fork is retired for an upstream that already did).
- syn 3 and webpki-roots 1.x are accepted *because* they are host-only
  (bolty CLI build/exec graph); if either ever enters a firmware graph,
  re-triage (size pressure on thumbv7em/xtensa).
- Advisories (deny.toml ignores RUSTSEC-2026-0190/0110/0173): re-verified
  still warranted 2026-10-19 — no fixed versions available for the pinned
  graph (anyhow unsound: no fix; bare-metal/proc-macro-error2:
  unmaintained, transitive).
