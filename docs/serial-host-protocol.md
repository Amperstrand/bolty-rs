# Serial host-protocol contract — burner firmware ↔ host

The contract for issue #92's "no more implicit protocol" task. Source of
truth: `apps/bolty-esp32/src/commands.rs::parse_command` (parser, host-
reviewable), `apps/bolty-esp32/src/console_framing.rs::LineAssembler`
(byte-level framing), and `apps/bolty-esp32/src/firmware/console_commands.rs::handle_line`
(dispatch + replies). The byte-level behavior is pinned by the tests in
`commands.rs` and `console_framing.rs` (`cargo test -p bolty-esp32`, the
esp32-check lane).

## Framing

- Transport: USB-CDC serial, one command per **ASCII line**; the device
  echoes nothing and evaluates each line as it completes.
- A line is `trim`med, then split on **ASCII whitespace** (any run of
  spaces/tabs). The first token is the command word, matched
  **case-insensitively**; remaining tokens are positional arguments.
  (The pre-dispatch words in the table below use the same framing via
  `commands.rs::parse_pre_dispatch_command`.)
- Empty/whitespace-only lines produce no reply on the serial console
  (`LineAssembler` skips them); `parse_command` itself classifies them
  as `UnknownCommand` (visible on the BLE transport, which feeds whole
  command strings into the parser).
- Length limits come from the fixed-capacity string types
  (`bolty-core/src/config.rs`): url/lnurl ≤ **256** bytes, ssid ≤ **32**,
  wifi-password ≤ **64**, rest-token ≤ **64**, ota-signature ≤ **128**.
  Overflow of any limit is `InvalidArgs`.
- Console lines are capped at **512** bytes
  (`console_framing.rs::MAX_LINE_LEN`). The byte that overflows the cap
  fails the line with `command too long` exactly once, and everything
  through the next newline is **discarded** — padding cannot smuggle a
  trailing command past the failure (issue #148).

## Reply convention

- Parse/dispatch failure: one `serial.fail(<message>)` line (message from
  `command_error_message`), and the display shows the failure.
- Success: per-command reply lines (`print_status`, `print_uid`, …) plus
  `[BOOT]`-style banner lines out of band; multi-line replies are freeform
  text terminated by the command's own final line.
- Long-running commands (`burn`, `wipe`, `check`) also surface completion on
  the display (`display::set_event`).

## Command table

| Command | Arguments | Parses to | Errors |
|---|---|---|---|
| `help` | none | `Help` (prints the command list) | `InvalidArgs` if extra |
| `i2cscan` | none | `I2cScan` | `InvalidArgs` if extra |
| `uid` | none | `Uid` | `InvalidArgs` if extra |
| `status` | none | `Status` | `InvalidArgs` if extra |
| `keys <k0> <k1> <k2> <k3> <k4>` | 5 × 32-hex-char (16-byte) AES keys | `SetKeys` | `MissingArgs` (<5); `InvalidArgs` (bad hex/length, >5) |
| `issuer [<hex16>]` | optional 32-hex issuer key | `Issuer` (get) / `SetIssuer` | `InvalidArgs` (bad hex, extra) |
| `url <lnurl>` | 1 arg, ≤256 bytes | `SetUrl` | `MissingArgs` / `InvalidArgs` (extra, >256) |
| `wifi <ssid> <password>` | 2 args (≤32 / ≤64) | `SetWifi` | `MissingArgs` (<2) / `InvalidArgs` (extra, overflow) |
| `wifi off` | literal `off` | `WifiOff` | `InvalidArgs` if extra |
| `ota <url> <signature>` | 2 args (≤256 / ≤128) | `Ota` | `MissingArgs` / `InvalidArgs` |
| `burn` | none | `Burn` | `InvalidArgs` if extra |
| `wipe` | none | `Wipe` | `InvalidArgs` if extra |
| `ndef` | none | `Ndef` | `InvalidArgs` if extra |
| `auth` | none | `Auth` | `InvalidArgs` if extra |
| `ver` | none | `Ver` | `InvalidArgs` if extra |
| `keyver` | none | `KeyVer` | `InvalidArgs` if extra |
| `check` | none | `Check` | `InvalidArgs` if extra |
| `inspect` | none | `Inspect` | `InvalidArgs` if extra |
| `picc` | none | `Picc` | `InvalidArgs` if extra |
| `diagnose` | none | `Diagnose` | `InvalidArgs` if extra |
| `derivekeys` | none | `DeriveKeys` | `InvalidArgs` if extra |
| `reset` | none | `Reset` | `InvalidArgs` if extra |
| `hwinfo` | none | `HwInfo` | `InvalidArgs` if extra |
| `button-mode [<mode>]` | optional `simple` \| `legacy` (case-insensitive) | `ButtonMode` (get) / `ButtonModeSet` | `InvalidArgs` (unknown mode, extra) |
| `token <value>` | `off` \| `none` \| `clear` (alias for unset) or token ≤64 bytes | `SetToken(None \| Some)` | `MissingArgs` if absent / `InvalidArgs` on >64 or surplus args |
| `crashlog` | none | pre-dispatch (`run_crashlog`): boot count + last crash | not via `parse_command`; surplus args → `UnknownCommand` |
| `hwtest` | none | pre-dispatch (`run_hwtest`): interactive hardware self-test | not via `parse_command`; surplus args → `UnknownCommand` |
| `provision-cert` | none | pre-dispatch: generate + store RSA-2048 self-signed TLS cert (needs `rest`) | not via `parse_command`; surplus args → `UnknownCommand` |
| `provision-ota-key <hex64>` | 64-hex-char Ed25519 public key | pre-dispatch: store OTA verification key (needs `ota`) | handler `fail` if length ≠ 64 or non-hex |
| `force [on\|off]` | optional `on` \| `off` | pre-dispatch: toggle/print the safety-check override | not via `parse_command`; unknown arg → `UnknownCommand` |
| *(anything else)* | — | — | `UnknownCommand` |

Five command words (`crashlog`, `hwtest`, `provision-cert`,
`provision-ota-key`, `force`) are matched by the console loop **before**
`handle_line`: they need loop-local state (buttons, NVS, feature-gated
provisioning) instead of the `dispatch_command` path. Their matchers
live beside `parse_command` (`commands.rs::parse_pre_dispatch_command`)
and are pinned by the same host tests, so generated clients see the real
surface (issue #148).

## Error taxonomy (exactly three)

- `UnknownCommand` — the first token matches no command (including empty lines).
- `MissingArgs` — a required positional argument is absent.
- `InvalidArgs` — an argument is malformed (hex length ≠ 32 chars, non-hex,
  unknown enum, fixed-capacity overflow) or surplus arguments are present.

## Security posture carried by the framing

- No binary framing, no length-prefixed fields: a hostile or glitched line
  can at worst produce one of the three parser errors — the parser is the
  trust boundary for the console. An overlong line fails whole and is
  drained to the next newline (`console_framing::LineAssembler`), so
  padding cannot smuggle a trailing command after the failure.
- Secrets (`keys`, `issuer`, `wifi`, `token`, `ota` signature) arrive as
  single arguments and are consumed into fixed-capacity storage; no
  heap growth is possible from line content.
