# Contributing to bolty-rs

## Development setup

### Host (desktop) development

All non-ESP32 crates build and test with a standard Rust toolchain:

```bash
cargo test --workspace --exclude bolty-esp32
cargo clippy --workspace --exclude bolty-esp32 -- -D warnings
cargo fmt --check
```

The `bolty-cli` desktop application needs `libpcsclite-dev` (Debian/Ubuntu) or
`pcsc-lite` (Homebrew) for PCSC smart card reader access.

### ESP32 firmware development

ESP32 builds require the `esp` Xtensa toolchain via `rustup`:

```bash
rustup toolchain install esp
rustup component add rust-src --toolchain esp
cargo +esp build --release -p bolty-esp32 --features "board-m5stick"
```

On macOS, set `RUSTUP_TOOLCHAIN=1.95.0` (or your host toolchain version) when
running host-side cargo commands if `rust-toolchain.toml` requests the esp
toolchain that isn't installed.

### Git hooks

Pre-commit hooks enforce `cargo fmt --check` and `cargo clippy` on host crates:

```bash
git config core.hooksPath .githooks
```

The hook excludes `bolty-esp32` from clippy (it needs the esp toolchain) and
uses `RUSTUP_TOOLCHAIN` override to bypass `rust-toolchain.toml`.

## Testing

### Host-side unit tests

164 tests across the workspace, all hardware-free:

```bash
cargo test --workspace --exclude bolty-esp32
```

### Integration tests with MockTransport

`bolty-cli` includes 11 integration tests that simulate the full NTAG424
protocol (AES-EV2 auth, file settings, key change, NDEF read/write, GetVersion)
via `MockTransport`:

```bash
cargo test -p bolty-cli --test integration
```

These tests cover the complete burn → wipe → re-burn lifecycle, diagnose, keyver,
picc, and version — all without physical hardware.

### Real card testing

Use `bolty-cli` with a PCSC reader (e.g. ACS ACR1252) on Linux:

```bash
cargo run -p bolty-cli -- diagnose --issuer-key 00000000000000000000000000000001
cargo run -p bolty-cli -- burn --issuer-key <KEY> --url <URL> --dry-run
cargo run -p bolty-cli -- burn --issuer-key <KEY> --url <URL>
```

Always run with `--dry-run` first to preview planned actions. Use `diagnose`
to check card state before and after operations.

## Card safety

See [`docs/card-safety.md`](card-safety.md) for the comprehensive NTAG424
safety reference. Key rules:

1. **Always run `diagnose` or `--dry-run` before burn/wipe**
2. **K0 (master key) is changed LAST** — factory K0 enables recovery until that step
3. **Never use `pcscd --debug` or `--apdu`** — these break reader hotplug
4. **Audit logs** are written to `/tmp/bolty-audit.log` by `LoggingTransport`
5. **Auth delay** is normal after failed attempts — wait 5-10s and retry

## CI pipeline

Three GitHub Actions workflows run on push and PR:

| Workflow | Purpose |
|---|---|
| `ci.yml` | fmt + clippy + test (workspace, excluding bolty-esp32) |
| `deny.yml` | cargo-deny license and advisory checks |
| `audit.yml` | cargo-aunt weekly security scan |

CI runs on Ubuntu with `libpcsclite-dev` installed and uses
`Swatinem/rust-cache` for build caching.

## Workspace structure

```
apps/
  bolty-cli/       Desktop CLI (PCSC) — burn, wipe, diagnose, picc, keyver, ver
  bolty-esp32/     ESP32 firmware (MFRC522) — serial/REST/OTA
crates/
  bolty-core/      Policy, derivation, crypto, PICC, assessment, UID, util
  bolty-ntag/      NTAG424 workflows: burn, wipe, safe_inspect, check_key_versions
  bolty-mfrc522/   MFRC522 reader transport
vendor/
  iso14443/        Vendored ISO/IEC 14443 protocol
  mfrc522/         Vendored MFRC522 driver
docs/
  architecture.md  Workspace topology and dependency boundaries
  card-safety.md   NTAG424 safety reference
```

## Dual-target design

All card operations are generic over `T: ntag424::Transport`. This enables:

- **Desktop**: `PcscTransport` (PC/SC reader via `pcsc` crate)
- **ESP32**: Custom transport over MFRC522 → ISO-DEP
- **Testing**: `MockTransport` (full protocol simulation)
- **Audit**: `LoggingTransport<T>` wraps any transport with APDU logging

The `Transport` trait is async with `transmit()` and `get_uid()` methods.
Card workflows in `bolty-ntag` work identically across all transports.
