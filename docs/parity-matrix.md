# Parity Matrix: C++ → Rust

Living acceptance matrix extracted from the C++ firmware headers named in task 4.

Wave 1–5 status: T1–T21 complete as of Wave 5.

## Hardware-Proven Features (tested on M5Atom + NTAG 424 DNA)

The following features have been verified end-to-end on real hardware with card UID `041065FA967380`:
- Full burn → inspect → wipe → check cycle
- NTAG424 AES authentication (patched `LenCap=0x03` in ntag424 crate)
- MFRC522 I2C transport at 400kHz
- Card-on-reader workflow (no lift/retap needed)

| C++ Feature | C++ File | Rust Target Crate | Rust Module | Status |
|---|---|---|---|---|
| Deterministic card key derivation (`CardKey = CMAC(issuer, 2D003F75 || uid || version_le)`) | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Deterministic K0 derivation | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Deterministic K1 derivation (issuer-key rooted, version-independent) | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Deterministic K2 derivation | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Deterministic K3 derivation | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Deterministic K4 derivation | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Deterministic CardID derivation | KeyDerivation.h | bolty-core | derivation | ✅ DONE |
| Hardcoded issuer key catalog | card_key_matching.h | bolty-core | derivation | ✅ DONE |
| Version candidate order `(1, 0, 2, 3)` | card_key_matching.h | bolty-core | derivation | ✅ DONE |
| URL query extraction for `p=` / `c=` | PiccData.h | bolty-core | picc | ✅ DONE |
| Hex validation and fixed-length hex decoding | PiccData.h | bolty-core | picc | ✅ DONE |
| PICC decryption (`p=` parameter) | PiccData.h | bolty-core | picc | ✅ DONE |
| PICC format byte validation (`0xC7`, UID present, counter present, UID len = 7) | PiccData.h | bolty-core | picc | ✅ DONE |
| Read counter decode (24-bit little-endian) | PiccData.h | bolty-core | picc | ✅ DONE |
| SV2 derivation vector builder | PiccData.h | bolty-core | picc | ✅ DONE |
| SDM session MAC key derivation (`CMAC(K2, SV2)`) | PiccData.h | bolty-core | picc | ✅ DONE |
| SDM CMAC verification (`c=` odd-byte truncation) | PiccData.h | bolty-core | picc | ✅ DONE |
| Combined PICC decrypt + verify flow | PiccData.h | bolty-core | picc | ✅ DONE |
| Deterministic K1 read-only decrypt helper | card_key_matching.h | bolty-core | picc | ✅ DONE |
| Deterministic K2 read-only CMAC helper | card_key_matching.h | bolty-core | picc | ✅ DONE |
| Card types / IdleCardKind | card_types.h | bolty-core | types | ✅ DONE |
| Key confidence model | card_types.h | bolty-core | types | ✅ DONE |
| `CardAssessment` struct/reset helper | card_types.h | bolty-core | assessment | ✅ DONE |
| Constant-time UID equality helper | card_types.h | bolty-core | assessment | ✅ DONE |
| Read-only card assessment engine | card_assessment.h | bolty-core | assessment | ✅ DONE |
| Assessment kind classification (`blank` / `programmed` / `unknown`) | card_assessment.h | bolty-core | assessment | ✅ DONE |
| Reset eligibility logic | card_assessment.h | bolty-core | assessment | ✅ DONE |
| Current issuer deterministic matching | card_assessment.h | bolty-core | assessment | ✅ DONE |
| Hardcoded issuer fallback matching | card_assessment.h + card_key_matching.h | bolty-core | assessment | ✅ DONE |
| Deterministic match result struct (`DeterministicBoltcardMatch`) | card_key_matching.h | bolty-core | assessment | ✅ DONE |
| Web key lookup fallback | card_assessment.h | bolty-esp32 | lookup | ⬜ OUT OF SCOPE (Wave 5+) |
| Serial whitespace trimming | serial_commands.h | bolty-core | commands | ✅ DONE |
| Serial space-delimited token parsing | serial_commands.h | bolty-core | commands | ✅ DONE |
| Serial command parser / dispatcher surface | serial_commands.h | bolty-core | commands | ✅ DONE |
| Serial PICC inspection command | serial_commands.h | bolty-core | commands | ✅ DONE |
| Serial inspect workflow | serial_commands.h | bolty-core | commands | ✅ DONE |
| Serial derivekeys workflow | serial_commands.h | bolty-core | commands | ⬜ OUT OF SCOPE (Wave 5+) |
| Serial diagnose workflow | serial_commands.h | bolty-core | commands | ⬜ OUT OF SCOPE (Wave 5+) |
| Serial recoverkey workflow | serial_commands.h | bolty-core | commands | ⬜ OUT OF SCOPE (Wave 5+) |
| Serial ChangeKey self-test (`testck`) | serial_commands.h | bolty-core | commands | ⬜ OUT OF SCOPE (Wave 5+) |
| Serial WiFi command (`wifi <ssid> <pass>` / `wifi off`) | serial_commands.h | bolty-core | commands | ✅ DONE (T16) |
| Burn/wipe/check/session/job constants | bolt.h | bolty-core | orchestration | ✅ DONE |
| Key version constants and hardware type constants | bolt.h | bolty-core | types | ✅ DONE |
| NTAG424 application/file constants | bolt.h | bolty-ntag | lib | ✅ DONE |
| NDEF record constants | bolt.h | bolty-core | ndef | ✅ DONE |
| SDM file-settings constants | bolt.h | bolty-core | ndef | ✅ DONE |
| Hex formatting/parsing helpers | bolt.h | bolty-core | util | ✅ DONE |
| Passive target scan helper | bolt.h | bolty-ntag | lib | ✅ DONE |
| Key version reading | bolt.h | bolty-ntag | lib | ✅ DONE |
| ISO authenticate helper | bolt.h | bolty-ntag | lib | ✅ DONE |
| ISO NDEF write helper | bolt.h | bolty-ntag | lib | ✅ DONE |
| `BoltcardKeys` parsing and LNbits fallback (`K3←K1`, `K4←K2`) | bolt.h | bolty-core | keyset | ✅ DONE |
| Reader selection helpers (`selectNtagApplicationFiles`, `selectNdefFileOnly`) | bolt.h | bolty-ntag | lib | ✅ DONE |
| NTAG424 scan-and-validate guard | bolt.h | bolty-ntag | lib | ✅ DONE |
| K0 authentication helper with card-presence diagnostics | bolt.h | bolty-ntag | lib | ✅ DONE — HW PROVEN |
| `changeAllKeys` reverse-order semantics (`4→0`, abort on first failure) | bolt.h | bolty-ntag | key_mgmt | ✅ DONE |
| Reader init / reinit logic | bolt.h | bolty-embedded | nfc | ✅ DONE |
| Burn workflow | bolt.h | bolty-core + bolty-ntag | orchestration | ✅ DONE — HW PROVEN |
| Burn guard: key 1 must still be factory | bolt.h | bolty-core + bolty-ntag | orchestration | ✅ DONE |
| NDEF construction with SDM placeholders | bolt.h | bolty-core + bolty-ntag | ndef | ✅ DONE — HW PROVEN |
| SDM file-settings programming | bolt.h | bolty-core + bolty-ntag | ndef | ✅ DONE |
| Burn post-write verification (new K0 auth + NDEF read) | bolt.h | bolty-core + bolty-ntag | orchestration | ✅ DONE |
| Wipe preflight key verification | bolt.h | bolty-core + bolty-ntag | key_mgmt | ✅ DONE |
| `verify_all_keys` probing (`K3=K1`, `K4=K2`, zero fallback) | bolt.h | bolty-core + bolty-ntag | key_mgmt | ✅ DONE |
| Wipe workflow + safety gate | bolt.h | bolty-core + bolty-ntag | orchestration | ✅ DONE — HW PROVEN |
| Reset-NDEF-only workflow + safety gate | bolt.h | bolty-core + bolty-ntag | orchestration | ✅ DONE |
| NTAG424 transport (MFRC522) | (Rust PoC) | bolty-mfrc522 | lib | ✅ DONE — HW PROVEN |
| NTAG424 card ops (burn/wipe/check) | (Rust PoC) | bolty-ntag | lib | ✅ DONE — HW PROVEN |
| REST auth split (read token vs write token) | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST JSON helpers / request body handling | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST card wait loop | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST status endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST UID endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST keys endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST URL endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST key version endpoint | bolty_rest_server.h | bolty-esp32 | rest | ⬜ OUT OF SCOPE (Wave 5+) |
| REST blank-check endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST burn endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST wipe endpoint | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17) |
| REST NDEF endpoint | bolty_rest_server.h | bolty-esp32 | rest | ⬜ OUT OF SCOPE (Wave 5+) |
| REST job endpoint | bolty_rest_server.h | bolty-esp32 | rest | ⬜ OUT OF SCOPE (Wave 5+) |
| HTTP server bootstrap + URI registration + mDNS | bolty_rest_server.h | bolty-esp32 | rest | ✅ DONE (T17, HTTP not HTTPS) |
| OTA firmware download + flash | ota.h | bolty-esp32 | ota | ✅ DONE (T18, no sig verification) |
| WiFi connection management | bolt.h + serial_commands.h | bolty-esp32 | wifi | ✅ DONE (T16) |
| LED/status display | gui.h / hardware_config.h / led.h | bolty-esp32 | led | ⬜ OUT OF SCOPE |
| Web key lookup | card_web_lookup.h | bolty-esp32 | lookup | ⬜ OUT OF SCOPE |
