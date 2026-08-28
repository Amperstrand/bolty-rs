# Parity & Audit Matrix

Status of (a) cross-implementation wire-format audits vs the reference
bolt-card implementations, and (b) capability parity between bolty-cli
(PCSC) and bolty-esp32 (firmware). Last full review: 2026-08-28.

## Cross-implementation wire-format audits

Reference implementations: **boltcard** (Go proxy, `boltcard/boltcard`),
**bolt-card-programmer** (TypeScript web app), the live edge worker
(`boltcardpoc.psbt.me`). Method: byte-exact fixture vectors generated from
the ORIGINAL implementation (`bolt-card-programmer/refchangekey.js`,
lesson B8) or line-by-line source comparison, pinned as tests.

| Surface | vs | Method | Status |
|---|---|---|---|
| p/c URL verification (`picc_verify_c`) | Go `check_cmac` | line-by-line + spec-quote pin | ✅ audited 2026-08-27 |
| ChangeKey K1–K4 (XOR+ver+CRC32) | TS app | byte-exact (ntag424 fork `change_key` parity) | ✅ 2026-08-27 |
| ChangeMasterKey K0 | TS app | byte-exact (same suite) | ✅ 2026-08-27 |
| FS_RESET / ChangeFileSettings | TS app | byte-exact (`change_file_settings` parity) | ✅ 2026-08-28 |
| AuthFirst/AuthSecond handshake | NXP AN12196 + TS app (transitive) | AN12196 APDU fixtures (ntag424 fork, 314 green) + session-key parity via command vectors + daily hardware auth | ✅ 2026-08-28: AuthFirst APDU pinned to AN12196 form (LenCap=0x03); SV1/SV2 session derivations verified transitively — the refchangekey.js session keys used by the ChangeKey/FS_RESET parity tests ARE the TS app's session-key construction, and every command-parity byte depends on them; plus every hardware burn/inspect authenticates |
| File read/write MAC exchanges (0xAD/0x8D) | any reference | — | ❌ pending |
| NDEF write bytes | TS app | — | ❌ pending |
| SDM URL templating (`[[{mac}`) | real worker + ACR1252 | hardware `mac=true` + live taps | ✅ hardware-audited |
| Full burn→tap→wipe lifecycle | live edge worker | HIL cycles (6× in one day, ALL PASS) | ✅ hardware-audited |
| Deterministic key derivation | spec fixtures + hardware | fixture tests + burn/tap round-trips | ✅ |
| Service-side counter/limits logic | Go proxy | — | ❌ pending (proxy repo) |

The parity fixtures live in the ntag424 fork
(`Amperstrand/ntag424@ai-experiments`, tests in `commands/change_key.rs`
and `commands/change_file_settings.rs`); regenerate vectors with
`node bolt-card-programmer/refchangekey.js`.

## Capability parity: bolty-cli vs bolty-esp32

| Capability | CLI (PCSC) | Firmware (MFRC522) |
|---|---|---|
| burn (derived / raw keys / proxy OTC) | ✅ | ✅ (derived/raw; proxy via REST `keys`+`burn`) |
| wipe | ✅ | ✅ |
| inspect / diagnose | ✅ | ✅ |
| keyver | ✅ (real read) | ✅ (via authenticated inspect path since `51e8a50`) |
| picc / SDM verify | ✅ | ✅ |
| try-key / scan-keys recovery | ✅ | ❌ (not exposed) |
| REST API | — | ✅ (TLS :81, token auth, job API) |
| OTA signed updates | — | ✅ (Ed25519; positive + negative HW-verified) |

## History

This file replaced a June-2026 "C++ → Rust port waves" matrix (T1–T21,
M5Atom-era) that described a pre-rig phase of the project; see git history
for the original content.
