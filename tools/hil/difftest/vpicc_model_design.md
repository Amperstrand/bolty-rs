# vpicc stateful NTAG424 model — design (rung plan)

Status: RUNG 1 IMPLEMENTED (2026-10-31) — vpicc_model.py answers 57/57
golden exchanges byte-exact (offline gate: check_model_vs_golden.py; live
pcsc round trip: test_vpicc_model.py). Rung 2 remains design-only.

## Why

`vpicc_golden.py` (PR #257) replays canned golden answers — it proves the
pcsc→vpcd→harness path but computes nothing. A STATEFUL model computes each
answer from emulated card state, so it can answer exchanges that were never
recorded (fuzz neighbors, different orderings, host tools' exploratory
probes) and, at rung 2, run real authenticated sessions. The golden then
becomes the model's regression test instead of its script.

## The golden's functional surface (what a model must reproduce)

Mined from `results/golden_acr1252.json` (59 replayable exchanges):

- **SELECT (00 A4)** — full ISO file-system state machine: MF (3F00), DF,
  AID (NTAG424 app AID vs invalid → 6A82), CC file select, NDEF file
  select, double-select stress, no-select-then-read rejection.
- **READ BINARY (00 B0)** — CC full/partial/invalid-offset, NDEF after
  select, Le edge cases (0x00 = max, oversized).
- **GetFileSettings (F5)** — CC and NDEF views, invalid file numbers.
- **Key version (C0)** — K0/K1 versions unauthenticated.
- **UID (CA/FFCA)** — FFCA is reader-side (never reaches the card); the
  CA-native variant is card-side.
- **Malformed class** — reserved INS (6E00-class), Lc mismatches,
  short headers, oversized Lc, Le edge: each with its exact golden SW.
- **read_sdm_no_select** — SDM metadata read attempt pre-select.

No AuthenticateEV2 appears in the golden — the capture is entirely
pre-auth. (The 91AD/91AE delay-ladder history is from card RECOVERY
sessions, not this capture.)

## Rung 1 — stateful pre-auth model (implementable without crypto)

`vpicc_model.py`: a `Ntag424State` object + `answer(state, capdu)`
dispatcher replacing the queue lookup in the vpicc chassis.

State: current file (None/MF/DF/AID-selected/CC/NDEF), file contents
(CC bytes and NDEF template from the golden's recorded reads — the DATA is
canned, the BEHAVIOR is computed), key-version table.

Rules (each pinned to its golden exchange in docstrings):
- SELECT walks the file tree; wrong AID → 6A82 (golden: select_by_aid_invalid).
- READ BINARY bounds-checks against the selected file's size; offset beyond
  → the golden's exact SW; partial reads return the tail.
- No file selected → the golden's rejection SW (read_no_select).
- Malformed parser: Lc/Le edge handling mirrors the golden's SW table.

Pass criterion: the existing `test_vpicc_golden.py` round-trip passes with
the MODEL as the answerer (59/59 byte-exact) — behavior-computed, not
replayed. Add `make difftest-vpicc-model` running the same test with the
model swapped in (env or flag).

## Rung 2 — authenticated surface (needs card-side crypto)

AuthenticateEV2 (0x71/0x77), ChangeKeyEV2, SDM reads. The card's side of
the session derivation (AES-CMAC over the AN12196 fields, session keys)
mirrors the host side that the `ntag424` crate already implements — the
formulas are in the crate; the model implements the card's obligations.
Test base: a NEW capture (an authenticated session against a burn card)
or vectors from the ntag424-vectors suite (#106). Only start after rung 1
is green against the golden.

## Out of scope (stays replay/hardware)

RF-level behavior, timing envelopes, auth-delay counters (rung 2+ if
ever), the physical-reader quirks the difftest exists to catch.
