# Serial host-protocol contract — burner firmware ↔ host

The contract for issue #92's "no more implicit protocol" task. Source of
truth: `apps/bolty-esp32/src/commands.rs::parse_command` (parser, host-
reviewable) and `apps/bolty-esp32/src/firmware/console_commands.rs::handle_line`
(dispatch + replies). The byte-level behavior is pinned by the tests in
`commands.rs` (`cargo test -p bolty-esp32`, the esp32-check lane).

## Framing

- Transport: USB-CDC serial, one command per **ASCII line**; the device
  echoes nothing and evaluates each line as it completes.
- A line is `trim`med, then split on **ASCII whitespace** (any run of
  spaces/tabs). The first token is the command word, matched
  **case-insensitively**; remaining tokens are positional arguments.
- Empty/whitespace-only lines are rejected as `UnknownCommand` (not
  ignored — the host gets feedback).
- Length limits come from the fixed-capacity string types
  (`bolty-core/src/config.rs`): url/lnurl ≤ **256** bytes, ssid ≤ **32**,
  wifi-password ≤ **64**, rest-token ≤ **64**, ota-signature ≤ **128**.
  Overflow of any limit is `InvalidArgs`.

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
| `token <value>` | `off` \| `none` \| `clear` (alias for unset) or token ≤64 bytes | `SetToken(None \| Some)` | `MissingArgs` if absent / `InvalidArgs` on >64 |
| *(anything else)* | — | — | `UnknownCommand` |

## Error taxonomy (exactly three)

- `UnknownCommand` — the first token matches no command (including empty lines).
- `MissingArgs` — a required positional argument is absent.
- `InvalidArgs` — an argument is malformed (hex length ≠ 32 chars, non-hex,
  unknown enum, fixed-capacity overflow) or surplus arguments are present.

## Security posture carried by the framing

- No binary framing, no length-prefixed fields: a hostile or glitched line
  can at worst produce one of the three parser errors — the parser is the
  trust boundary for the console.
- Secrets (`keys`, `issuer`, `wifi`, `token`, `ota` signature) arrive as
  single arguments and are consumed into fixed-capacity storage; no
  heap growth is possible from line content.
