# Wire-capture & interop methodology — NTAG424 A/B (2026-10-27)

Research + application session. Sources: Ludovic Rousseau (pcsc-lite/CCID
maintainer) "CCID USB spy using Wireshark" (2014), "Wireshark better at
decoding CCID protocol" (2023), "ISO 7816-4 spy using Wireshark" (2019);
Wireshark wiki CaptureSetup/USB; ask.wireshark.org threads. The
pcsc-native standard for smart-card wire capture is **usbmon → pcap →
Wireshark's built-in CCID dissector → ISO 7816-4 APDUs** — no custom
tooling required for viewing.

## What we run

1. **Real-wire capture (silicon)**: `sudo modprobe usbmon` on
   ai-legion-small; `dumpcap -i usbmon1` (ACR1252 bus) during the test
   battery. Result: `silicon-battery.pcapng` — opens in Wireshark with
   native CCID dissection (383+ CCID frames per battery; verified with
   tshark: bMessageType 0x80 XfrBlock / 0x81 DataBlock etc).
   NOTE: dumpcap drops privileges — write to a world-writable dir.
2. **APDU-vector layer (both sides)**: `wire_tap.py` converts a bolty
   audit log into JSONL vectors: one object per exchange — command name
   (NTAG424 INS map), APDU hex + structural fingerprint (crypto-random
   bodies masked), response SW, AN12196-style status classification,
   lengths. Same format for silicon and virtual samples.
3. **Virtual side**: the vpcd bridge transcript (>>/<< APDU log) converts
   to the same JSONL via the same classifier. (A Wireshark Lua dissector
   for the vpcd TCP framing is future work; the JSONL layer serves
   machine diffing today.)
4. **A/B structural diff**: `ab_diff.py` — LCS alignment over
   (command, status-class) pairs with masked fingerprints; reports
   aligned/only-A/only-B slots.

## Recorded samples (this session)

| Artifact | Content |
|---|---|
| silicon-battery.pcapng | usbmon capture: f5-probe + 2 burn cycles on real NTAG424 04C474FA967380 (Wireshark-renderable) |
| silicon-audit.log → silicon.wire.jsonl | 3286 exchanges, full battery |
| sim.wire.jsonl | 304 exchanges from the fixed-applet vpcd session (incl. preserved pre-fix 911E probes) |
| silicon-run/ | harness transcripts + per-cycle summaries (ALL PASS incl. live taps) |

## Results

- **Silicon Tier 1 (the keystone)**: f5-probe interleave on REAL NTAG424,
  ZERO compat flags: **F5 3/3 + AD 3/3, F5 2/2 + 8D 1/1** — identical to
  the fixed applet. The CmdCtr root-cause model is silicon-confirmed.
- **Full Phase A on silicon**: 6/6 burn→inspect→picc→live-tap-200→wipe→
  blank cycles ALL PASS on 04C474FA967380 (the original mission card).
- **A/B structural parity**: 300/304 (98.7%) of the virtual sample's
  exchanges align 1:1 with silicon by (command, status-class). The 4
  divergent slots: 2 preserved pre-fix 911E probes, 1 documented
  jcardsim sendBytes truncation (ISO-ReadBinary 0003), 1 probe-only
  plain read.

## Reuse

    # silicon capture
    ssh small 'sudo modprobe usbmon; mkdir -m 777 /tmp/wire'
    ssh small 'sudo dumpcap -i usbmon1 -w /tmp/wire/x.pcapng -q &'
    <run battery>
    ssh small 'sudo pkill -INT dumpcap'
    # vectors + diff
    wire_tap.py audit.log -o a.wire.jsonl
    ab_diff.py a.wire.jsonl b.wire.jsonl

## Known limitations / next

- jcardsim direct-transmit truncates >=256B/Le-0 responses (T4T test
  disabled upstream-candidate; silicon unaffected).
- vpcd poll-race occasionally mangles first-transmit SW (retry
  signatures in the harness cover it; root fix belongs in the vpcd ifd).
- vpcd Wireshark dissector (Lua) would complete the "everything renders
  in Wireshark" story.
- The nucula (PN7160) and MFRC522 axes: not captured this session —
  same wire_tap format applies once their host paths emit APDU logs.

## vpcd.lua Wireshark dissector (added this session)

Renders the vpcd TCP protocol natively in Wireshark/tshark — completes
the "everything renders in Wireshark" story for the virtual axis:

- length-prefixed framing with TCP desegmentation
- power control classification (OFF/ON/RESET/PROBE-ext)
- C-APDU side: CLA/INS + NTAG424 command names (AuthFirst, GetFileSettings,
  ReadData, ChangeKey, ...) 
- R-APDU side: data/SW split + AN12196 status classes (NTAG-OK,
  ADDITIONAL-FRAME, AUTH-ERROR, INTEGRITY-ERROR, ...)
- direction from ports: the vpcd ifd LISTENS (src==port => reader->card)

Verified against a captured f5-probe session (vpcd-f5probe-sim.pcap):
the C-APDU AuthFirst -> R-APDU ADDITIONAL-FRAME -> AuthSecond/Chain ->
NTAG-OK chain renders as readable pairs. Load:
  tshark -X lua_script:vpcd.lua -r capture.pcap -Y vpcd
or copy to ~/.local/lib/wireshark/plugins/ for the GUI.

Gotchas learned (Wireshark Lua 5.2 API): pinfo.src_port (not
pinfo.src.port); ProtoField variables must match exactly in
vpcd.fields; desegment_len for multi-segment frames.
