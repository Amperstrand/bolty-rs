# ntag424 upstream feed packet (durable home)

Owner-staged submission to **jannschu/ntag424** (Codeberg) — nothing
posted; per the CHANNEL rule the owner does all posting to non-member
repositories. Decision + research record: issue #109 and fork-policy §4
(KEEP the fork; feed when the owner chooses; upstream dormant since
2026-05-26, nothing to merge in).

Contents:

- `patches/` — `git format-patch f540830..upstream/lencap` from the
  Amperstrand/ntag424 fork: 7 commits through `6f39a47` (LenCap=0x03
  fix, `Sdm::disabled()`, licensing docs, reference-parity tests,
  fixture regen, fmt). Verified applying cleanly to upstream main
  `f540830`.

  Rationale scrub (2026-10-30): patch 0002/0005/0006 wording corrected —
  the original comment claimed the card *rejects* LenCap=0x00, refuted by
  issue #3's own hardware A/B (both encodings pass on NTAG 424 DNA ×
  MFRC522 + ACR1252) and by NXP AN12196 Tables 14/19, whose worked
  examples send LenCap=0x00 (`90 71 00 00 02 [KeyNo] 00 00`). The change
  is explicit AES-128/PCDcap2 signaling per the Table 25 encoding — a
  functional no-op. Matches ntag424 fork issue #10 (open) and PR #6's
  direction; series re-verified to apply cleanly to `f540830`.
- Post-from-here convenience copy with the guide files:
  `/tmp/opencode/ntag424-feed-packet/` (OWNER_STEPS.md + PR text) — the
  /tmp copy is regenerable from THIS directory at any time:
  `cp docs/ntag424-feeding/patches/*.patch /tmp/opencode/ntag424-feed-packet/patches/`
  (this durable home exists because the original 2026-10-19 /tmp packet
  was wiped; regenerated 2026-10-23, byte-same series).

Owner steps (short form — full version in the /tmp OWNER_STEPS.md):
co-sign gate RESOLVED (PR #131 + #109 record); expect slow review;
never block on uptake (pins stay on the fork).
