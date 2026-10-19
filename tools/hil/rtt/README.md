# RTT offline decode tools (STM32 bench)

`probe-rs run`/`attach` (0.32) does not print RTT on the shared F469
bench while firmware sits in WFI — scans at the exact control-block
address fail despite a perfect header in RAM (full analysis:
docs/stm32-bringup-2026-10-19.md). The reliable capture path:

```bash
# 1. flash + reset (never a bare st-flash write — wedge table in ccid AGENTS)
st-flash --connect-under-reset --serial <stlink-serial> write <bin> 0x08000000
st-flash --connect-under-reset --serial <stlink-serial> reset

# 2. halt-and-read SRAM (first read after a gdb session can come back
#    empty — just retry once)
st-flash --serial <stlink-serial> read dump.bin 0x20000000 0x11000

# 3. decode (tag table from the ELF, frame split, per-frame print)
python3 tools/hil/rtt/decode_rtt.py <elf> dump.bin

# 4. byte-exact verification of any frame that matters (forward
#    encoder simulation vs observed wire bytes)
python3 tools/hil/rtt/verify_frames.py dump.bin <tag-and-ts-hex> ...
```

Notes:

- defmt's build config is load-bearing for any of this to show output:
  `DEFMT_LOG` baked at build time (`.cargo/config.toml [env]`), no
  `strip` in release, `debug = 2`, `-Tdefmt.x`. All four are documented
  in docs/stm32-bringup-2026-10-19.md.
- defmt-1.x-internal argument encoding carries type-marker bytes the
  naive decoder does not fully model — when an arg's meaning matters,
  prove it with verify_frames.py (and, on the bench, a gdb breakpoint
  on the log call site; that is how the NFC-prep build's "scan found 0
  devices" line was confirmed live on 2026-10-19).
- Provenance: tools extracted from the 2026-10-19 bring-up session
  (evidence pack /tmp/opencode/bolty-stm32-bringup/ on ai-legion);
  byte-exact against two independent boots for both the skeleton and
  the NFC-prep builds.
