# bolty-rs

`bolty-rs` is a Rust-native Bolt Card workspace targeting **both** ESP32 firmware (MFRC522 NFC frontend) and desktop CLI (PCSC smart card readers). The ESP32 firmware supports **M5StickC Plus** and **M5Atom Matrix**, both wired to MFRC522 over I2C. The desktop CLI (`bolty-cli`) provides card programming operations via any PC/SC reader on Linux/macOS. The project is serial-driven by default, with optional WiFi/REST/OTA support behind feature flags.

## Current state

- Full Bolt Card lifecycle: `burn`, `wipe`, `diagnose`, `inspect`, `keyver`, `ver`, `picc`, `url`, `derive-keys`, `cycle`, `try-key`, `scan-keys`, `reset-card`, `test-ck`
- Desktop CLI (`bolty-cli`) with pre-flight safety checks, per-key verification, `--dry-run` mode, `--json` output, `--force` override, card recovery tools, and circuit breaker
- ESP32 firmware with serial console, optional WiFi/HTTPS REST API (bearer token auth, self-signed TLS), BLE transport (NimBLE, encrypted, read-only whitelist, opt-in), OTA updates (Ed25519 signed), and `token` command for REST API authentication
- Comprehensive hardware-free test suite including integration tests via MockTransport (full NTAG424 protocol simulation), property-based crypto testing with proptest (#36), and security regression test suite (#41)
- Both supported boards (M5StickC Plus, M5Atom Matrix) build from the same firmware crate with compile-time board selection
- Hardware-verified on PCSC (ACS ACR1252) and M5StickC Plus (MFRC522 I2C)
- Dependency versions pinned exactly, `Cargo.lock` tracked for reproducible builds
- Key provenance tracking in audit log (#39) — track key source (factory/derived/raw) per operation
- Formal card lifecycle state machine (#40) — explicit state transitions with validation

## Workspace architecture

```mermaid
flowchart TD
    host[Serial client / HTTP client] --> app[apps/bolty-esp32]
    cli[Desktop CLI / PCSC] --> cliapp[apps/bolty-cli]
    app --> core[crates/bolty-core\nderivation + assessment + config]
    app --> ntag[crates/bolty-ntag\nNTAG424 workflows + facade]
    app --> mfrc[crates/bolty-mfrc522\nMFRC522 transport]
    app --> idf[esp-idf-sys / hal / svc]
    cliapp --> core
    cliapp --> ntag
    cliapp --> pcsc[pcsc crate]
    ntag --> ntag424[ntag424 crate]
    mfrc --> iso[vendor/iso14443]
    mfrc --> raw[vendor/mfrc522]
    mfrc --> card[MFRC522 reader]
    ntag --> boltcard[NTAG424 card]
    pcsc --> creader[PCSC reader]
    cliapp --> boltcard
```

See also [`docs/architecture.md`](docs/architecture.md) and [`docs/parity-matrix.md`](docs/parity-matrix.md).

## Supported boards and capability model

| Board feature | Current NFC frontend | Capability features implied | Notes |
|---|---|---|---|
| `board-m5stick` | `nfc-mfrc522` | `display-st7789` | M5StickC Plus + MFRC522 on G32/G33 |
| `board-m5atom` | `nfc-mfrc522` | `led-matrix` | M5Atom Matrix + MFRC522 on G26/G32 |

Additional optional runtime services:

| Feature | Meaning |
|---|---|
| `wifi` | Enable WiFi connect/disconnect commands |
| `rest` | Enable REST API (implies `wifi`) |
| `ota` | Enable OTA update command (implies `wifi`) |

`display-st7789` ships a working status UI on M5StickC Plus (boot state,
card UID + state, battery/USB indicator, command results, battery-poll
redraw guard) — hardware-verified since 2026-08-24. Future NFC frontends
such as PN532 should follow the same pattern as a separate frontend
capability rather than being hidden inside board selection.

## Build and flash

Build from **inside `apps/bolty-esp32/`** — its `.cargo/config.toml` supplies the
`xtensa-esp32-espidf` target and `-Zbuild-std` settings. Building from the
workspace root compiles a useless host (x86-64) binary instead:

```bash
cd apps/bolty-esp32

# M5StickC Plus
cargo +esp build --release --features "board-m5stick"

# M5StickC Plus with WiFi + REST
cargo +esp build --release --features "board-m5stick,wifi,rest"

# M5Atom Matrix
cargo +esp build --release --features "board-m5atom"
```

The binary lands in the **workspace** target dir. Flash it from the workspace
root (espflash's default 115200 baud is reliable on the M5StickC FT232 link;
higher rates drop bytes):

```bash
cd ../..
espflash flash --port /dev/ttyUSB0 target/xtensa-esp32-espidf/release/bolty-esp32
```

Custom partition tables are supplied at flash time
(`espflash flash --partition-table <csv>`) — `CONFIG_PARTITION_TABLE_CUSTOM`
in `sdkconfig.defaults` does not work with esp-idf-sys cargo builds
(esp-rs/esp-idf-sys#395).

Exactly one board feature must be enabled for firmware builds.

## Desktop CLI (bolty-cli)

`bolty-cli` provides card programming operations via any PC/SC reader (e.g. ACS ACR1252). It requires `libpcsclite-dev` on Linux or `pcsc-lite` on macOS.

```bash
# Install pcsc dependency (Ubuntu)
sudo apt install libpcsclite-dev

# Build
cargo build -p bolty-cli

# Diagnose card state (read-only, safe)
cargo run -p bolty-cli -- diagnose --issuer-key 00000000000000000000000000000001

# Preview burn without touching the card
cargo run -p bolty-cli -- burn --issuer-key <KEY> --url <URL> --dry-run

# Burn card (writes NDEF, enables SDM, installs derived keys)
cargo run -p bolty-cli -- burn --issuer-key <KEY> --url <URL>

# Read key versions (requires K0 auth)
cargo run -p bolty-cli -- keyver --issuer-key <KEY>

# Wipe card (factory reset)
cargo run -p bolty-cli -- wipe --issuer-key <KEY>

# Card recovery: try a specific raw key
cargo run -p bolty-cli -- try-key --key 11111111111111111111111111111111

# Card recovery: scan all likely key candidates
cargo run -p bolty-cli -- scan-keys --issuer-key <KEY>
```

All APDU exchanges are logged to `/tmp/bolty-audit.log`. See [`docs/card-safety.md`](docs/card-safety.md) for the complete safety reference.

## REST and network discovery

When built with `wifi,rest`, the device exposes an HTTP API and advertises itself over mDNS as `bolty.local`.

Typical Linux discovery commands:

```bash
# Resolve the hostname (requires Avahi or another mDNS resolver)
avahi-resolve -n bolty.local

# Browse advertised HTTP services
avahi-browse -r _http._tcp

# Broadcast DNS-SD discovery with nmap
nmap --script broadcast-dns-service-discovery
```

If `bolty.local` does not resolve, verify that the host has mDNS enabled (`avahi-daemon` or `systemd-resolved`) and that UDP/5353 is not blocked. Do not confuse the router address with the device address; `192.168.13.1` is typically the gateway, not the ESP32.

## Spec conformance (greatspectations)

Spec-relevant code carries verbatim boltcard-spec quotes as comments
(`// BOLT_SPEC:`, `// BOLT_DET:`, `// BOLT_PRIV:` markers for
[spec/docs/SPEC.md](https://github.com/boltcard/boltcard/blob/main/docs/SPEC.md),
DETERMINISTIC.md, and CARD_PRIVACY.md). CI (`.github/workflows/spec-quote-drift.yml`)
verifies every quote against a fresh clone of the spec, so comments claiming
spec behavior cannot drift silently. Cross-implementation audits (e.g. the
p/c verification vs the Go boltcard proxy's `check_cmac`) are recorded in
`Audited ... against ...` comments at the audited site.

```bash
git clone --depth=1 https://github.com/boltcard/boltcard.git spec
python -m greatspectations check --config specquotes.toml \
  --comment-start '// ' --comment-continue '//' -k \
  $(git ls-files 'crates/bolty-core/src/*.rs' 'crates/bolty-ntag/src/*.rs')
```

NXP-layer wire formats (datasheet, AN12196) have no canonical text source and
are guarded by byte-exact fixture vectors instead.

## Repository hygiene and dependency policy

- Direct dependency versions are pinned with `=x.y.z` syntax.
- The NFC fork crates (mfrc522, iso14443, ntag424) come from Amperstrand forks, always pinned by rev — see [`docs/fork-policy.md`](docs/fork-policy.md).
- The workspace `Cargo.lock` should be committed to freeze transitive versions for reproducible firmware builds.
- Local files such as `.env`, `.env.*`, `.direnv/`, `.envrc`, `.embuild/`, and editor caches are ignored.
- WiFi credentials must never be committed. Use runtime serial commands or local ignored files only.

## Improvement areas already identified

- Re-enable `display-st7789` and verify NFC + display coexist on M5StickC Plus hardware (display driver code exists, feature is wired into `board-m5stick`).
- Add I2C bus recovery (SCL toggle) before `I2cDriver` init for robustness against stuck-bus conditions.
- Add MFRC522 init retry with backoff (currently single attempt; vendor `init()` consumes the bus on failure).
- Introduce a separate PN532 frontend when that transport is added, rather than overloading board features.

## Contributing

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for development setup, git hooks, testing guide, and dual-target workflow. See [`docs/card-safety.md`](docs/card-safety.md) for the NTAG424 safety reference.
