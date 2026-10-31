# ISSUE DRAFT — for owner review before posting to frankmorgner/vsmartcard
# (CHANNEL rule: owner posts to non-member repos. Post via web UI so the three
#  pcaps can be drag-dropped as attachments. Do NOT post the 9-line e484c2c8
#  patch as the proposal — it hangs against spec-compliant vpicc, see C1.)

**Title:** Protocol clarity: vpicc implementations that answer RESET desync the
driver's TCP stream (wire evidence + repro)

---

## Summary

The documented protocol table says OFF/ON/**RESET** get **no response** — only
Get ATR and APDU are answered. That is easy to miss for implementers who model
real card behavior, because in ISO 7816 a reset *does* return an ATR. A vpicc
that answers `0x02 (RESET)` with the ATR desynchronizes `vpcd`'s TCP stream: the
stale ATR is later delivered to whichever `recvFromVICC()` runs next (an ATR
probe or an APDU transmit), surfacing as garbage status words (ATR tail bytes).

We hit this with Java-Card-style simulators on our bench; filing because the
failure mode is silent, intermittent (~50% on first exchange after connect in
our case), and takes real wire captures to diagnose. Everything below is
software-only and reproducible without hardware.

## Mechanism

`vicc_reset()` sends `0x02` without receiving, while `vicc_getatr()` /
`vicc_transmit()` pair send+receive under the same lock. pcscd's reset flow
(`ifd-vpcd.c`: `IFDHPowerICC(IFD_RESET)` → `vicc_reset()` → unconditionally
`IFDHGetCapabilities(TAG_IFD_ATR)` → `vicc_getatr()`) therefore queues

    driver: [RESET][GET_ATR]          (often merged into one TCP segment)
    vpicc:  [ATR][ATR]                (if the vpicc answers RESET)

`vicc_getatr()` consumes the RESET's ATR; the GET_ATR reply goes stale and is
returned to the next unrelated receive.

## Wire evidence (attachment A1-desync.pcap)

    0.000000  driver->vpicc  0001 02 0001 04     RESET + GET_ATR (merged)
    0.000119  vpicc->driver  0003 3bff01         ATR #1 (RESET's reply)
    0.000191  vpicc->driver  0003 3bff02         ATR #2 (GET_ATR's reply -> stale)
    0.000268  driver->vpicc  0001 04             presence probe
    0.000301  driver->vpicc  0007 00a40400023b00 APDU
    0.000328  vpicc->driver  0003 3bff03         ATR #3 (probe's reply)
    0.000394  vpicc->driver  0003 019000         R-APDU (arrives, never read)

The application's transmit received ATR #3 as its "R-APDU" (SW = ATR tail).
A2-control.pcap shows the identical driver sequence against a spec-silent vpicc:
clean.

## The naive fix is a trap (attachment C1-fixed-spec-hang.pcap)

"Consume the response after sending RESET" fixes the desync — but against a
spec-compliant (silent) vpicc the extra `recvFromVICC()` blocks forever
(`recvall()` is `MSG_WAITALL`, no timeout). Our C1 run: the entire capture is a
single frame `0001 02`; the driver sat in `vicc_reset()` until we killed it.
A poll-bounded drain works for both worlds but adds a tuning tradeoff (window
must exceed the responder's latency; silent vpiccs pay the full window per
reset). We are NOT proposing either patch — documenting the hazard.

## What we surveyed (ecosystem census, 2026-10-30)

**Spec-silent on RESET — 14+ implementations**, several documenting the rule in
their own comments:
- Upstream: `VirtualSmartcard.py` (reference), `pcsc-relay/src/vicc.c` ("ignore
  reset, power on, power off"), `remote-reader` `VPCDWorker.java`, Windows
  `BixVReader` (same `vicc_*` library, send-without-recv)
- Third-party: onomondo/onomondo-uicc (C softsim), Fluepke/konnektor-patch
  (verbatim reference copy), PL4typus/virt_cacard (embeds the protocol table:
  "Reset → No Response"), julijonas/apdu-intercept, GuruSteve/SubspaceRelay
  (logs "reset (no response)"), netget-net/netget (Rust; comments state the rule
  AND that the reader follows reset with an ATR request), cryptick-token-daemon
  (Rust; "Reset → nothing"), yakisoba0728/localkey (Rust; "No answer"),
  alun-hub/remote-smartcard (Rust; "no response expected"), Nitrokey's `vpicc`
  crate (Rust, docs.rs — silent), mrwhizzy/WiFi-Smartcard (vendored 0.8)
- Maintainer's own words in #124: "vpcd initiates all communication in sending a
  request (e.g. GET ATR) and expecting a response"

**Answers RESET with the ATR — 2 known:**
- Our Java-Card-style bench simulators (still answer RESET as of 2026-10-30;
  migrating to spec-silence — coordinated with rolling back the fork driver on
  one host that currently expects the reply)
- **jaesharp/simrs** (independent Rust SIM simulator, `crates/simrs-vpcd`):
  sends the ATR in its RESET arm while explicitly noting "vpcd does not expect
  a response to Power Off" — i.e. a careful author read the protocol, got OFF
  right, and still chose reset→ATR. With stock vpcd this implementation is
  exposed to the desync below on any reset path.

The failure signature (garbage SWs that are actually ATR tail bytes) is
currently undocumented anywhere we could find — this issue would be the first
indexed description, which is the main search-rescue value.

## Proposals (any/all welcome)

1. **Docs emphasis:** a sentence in the protocol section noting that control
   messages other than Get ATR expect **no** response, and that answering RESET
   (natural if you model ISO 7816 semantics) desyncs the stream.
2. Optionally, a poll-bounded drain in `vicc_reset()` as a compatibility shim.
3. We are aligning our own emulators with the table. Note for implementers doing
   the same: "no response" must be **true silence** — a zero-length reply is
   worse than answering (the driver's next Get ATR reads the empty frame as a
   0-byte ATR → "card removed" ejection); verified on our bench.

## Repro (no hardware, seconds to run)

Gist: <LINK — publish vpcd-ab rig: harness.c, vpicc_sim.py, recproxy.py,
run_scenario.sh, plus the three pcaps>. Compiles your `vpcd.c` unmodified
(`gcc -DHAVE_CONFIG_H harness.c vpcd.c lock.c -lpthread`), drives the exact
pcscd sequence, and writes the pcaps above.
