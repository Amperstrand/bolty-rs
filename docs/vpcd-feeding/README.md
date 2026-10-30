# vpcd evidence pack (durable home)

Everything needed to re-verify and post the vpcd RESET-desync findings —
moved out of a volatile `/tmp` session dir (precedent: the 2026-10-19
ntag424 feed packet was lost to a /tmp wipe once already).

Context: bolty-rs #226 (root cause CORRECTED 2026-10-30 — see the issue),
ccid-firmware-rs PR #509 (the fix at source). Upstream vsmartcard was
never buggy: the official protocol table (frankmorgner.github.io/
vsmartcard, "Creating a Virtual Smart Card") answers only Get ATR and
APDUs; our emulators (and exactly one external implementation,
jaesharp/simrs) answered RESET with the ATR, desyncing the driver's
uncorrelated TCP stream — the SW=1084/1790/171a signatures are ATR tail
bytes.

## Contents

- `ISSUE-DRAFT.md` — owner-staged upstream issue (docs emphasis + hazard
  documentation; explicitly NOT proposing the consume-patch, which hangs
  against spec-silent vpicc). Owner posts per the channel rule.
- `rig/` — self-contained reproduction:
  - `harness.c` — drives REAL vpcd.c through pcscd's exact sequence
    (ifd-vpcd.c: IFDHPowerICC(RESET) → vicc_reset → vicc_getatr →
    vicc_present → vicc_transmit); SIGALRM converts indefinite blocking
    into exit 42
  - `vpcd-upstream-93286a90.c` — pristine upstream (identical to
    frankmorgner/vsmartcard@master at that SHA)
  - `vpcd-e484c2c8.c` — the Amperstrand fork's consume-fix branch
  - `vpcd-guarded-drain.c` — poll-bounded drain prototype
    (VPCD_DRAIN_MS, default 50)
  - `lock.c/h`, `vpcd.h`, `config.h` (autotools stand-in:
    HAVE_DECL_MSG_NOSIGNAL 1, as ./configure produces on Linux)
  - `vpicc_sim.py` — vpicc simulator, modes: spec / deviant (answers
    RESET, mirroring the bench convention) / zeroack (RESET → 0-length
    frame — the eject hazard)
  - `recproxy.py` — TCP recording proxy; writes Wireshark-decodable
    pcaps (LINKTYPE_RAW; tshark-verified)
  - `run_scenario.sh`, `run_e2e.sh` — runners
- `captures/` — the A/B/C/D/E matrix + full-stack E2E (pcaps + driver
  logs; emulators/pcaps are fully synthetic — self-marked test traffic,
  no bench data):

| run | driver × vpicc | result |
|---|---|---|
| A1 | upstream × deviant | DESYNC — transmit got stale ATR, SW = ATR tail |
| A2 | upstream × spec | clean (control) |
| B1 | e484c2c8 × deviant | clean (consume works in this world) |
| C1 | e484c2c8 × spec | HANG — SIGALRM exit 42; pcap = one frame |
| D1/D1b/D2b/D2c | guarded drain | tuning tension quantified |
| E1 | upstream × zeroack | slot death — getatr→0 → vicc_eject |
| E2E-ORIGINAL | upstream × REAL vpicc_table.py (pre-fix) | **SW=1084** — the production signature |
| E2E-FIXED | upstream × REAL vpicc_table.py (PR #509) | clean — own R-APDU, paired frames |

## Rebuild & rerun

    cd rig
    for v in upstream e484c2c8 guarded-drain; do
      gcc -O1 -g -Wall -DHAVE_CONFIG_H -o drv_$v harness.c vpcd-$v.c lock.c -I. -lpthread
    done
    ./run_scenario.sh <name> <upstream|e484c2c8|guarded-drain> <spec|deviant|zeroack> <idx>
    # (guarded-drain: VPCD_DRAIN_MS=<ms> to vary the window)

Binaries are not tracked; regenerate with the line above.

Provenance: upstream sources GPL-3 (frankmorgner/vsmartcard), headers
intact; vpcd-upstream fetched 2026-10-30 from Amperstrand/vsmartcard
@master, which is 0/0-identical to frankmorgner@master (verified via gh
compare). Ecosystem census (14+ spec-silent implementations incl.
Nitrokey's vpicc crate; 2 RESET-answerers) and the full audit trail:
`.audit-lanes/lane-nfc.md` in project-context + bolty-rs #226.
