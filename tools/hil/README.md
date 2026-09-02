# HIL tooling — bolty console daemon + card lifecycle cycle

Host-side hardware-in-the-loop tooling for the M5StickC Plus rig
(ai-legion-small). Solves the two failure classes that made the rig
undependable:

## Why a daemon (lesson B11)

Every `open()`/`close()` of the FT232 USB-UART fires DTR/RTS TIOCMSET
transitions that corrupt this bridge's USB state machine — the device
disconnects from the bus (11 events in the lab box kernel log) and needs a
USB rebind to recover. Additionally, ModemManager probes every new ttyUSB
enumeration, racing real clients for the port.

Fixes, in order of importance:

1. **`bolty-console.py`** — opens the port exactly ONCE at boot and serves
   line commands over a unix socket. Tooling never touches the tty again.
   All RX is journaled to `~/.bolty/console.log` for post-mortems.
2. **`99-bolty-stick.rules`** — udev: `ID_MM_DEVICE_IGNORE` for the FT232
   (the box has no modems) and `power/control=on` (no runtime suspend).
3. **`bolty-console.service`** — systemd unit, `BindsTo` the serial device
   unit so the daemon cleanly restarts across USB re-enumerations.

## Install (once per lab box)

```bash
sudo install -m 644 tools/hil/99-bolty-stick.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo install -m 644 tools/hil/bolty-console.service /etc/systemd/system/
# edit the unit if the repo lives elsewhere than ~/src/bolty-rs
sudo systemctl daemon-reload && sudo systemctl enable --now bolty-console
python3 tools/hil/bolty-ctl.py PING   # -> alive hb_age=2s ...
```

## Usage

```bash
bolty-ctl status                 # any console command
bolty-ctl PING                   # daemon health
bolty-ctl RAW 10                 # passive 10s capture
python3 tools/hil/burn_cycle.py  # full lifecycle test (see its docstring)
```

## Cycle semantics (lesson B12)

`burn_cycle.py` defaults to the PUBLIC deterministic issuer key
(`0000…0001`, v1) because boltcardpoc.psbt.me can only route an anonymous
tap via deterministic keys — percard CSV rows require knowing the UID
before decrypting p=, which an anonymous first tap cannot provide. Raw-key
(`--keys`) burns remain supported for deployments that know their keys.

Verified cycle (2026-08-25): burn → `sdm=ok uid_match=true` → live worker
`HTTP 200 withdrawRequest` → wipe → `state=blank`, zero port wedges across
the whole session.

## Proxy healthcheck

`proxy.psbt.me` (the bolt-card worker the HIL tap depends on) intermittently
returns HTTP 530 — Cloudflare error 1033, tunnel down (observed 2026-08-26/27;
caught live again 2026-08-27 18:25). While down, every card tap silently
fails. Install the 5-minute monitor on the lab box:

```bash
sudo install -m 755 tools/hil/proxy_healthcheck.sh /usr/local/bin/bolty-proxy-healthcheck
sudo install -m 644 tools/hil/proxy-healthcheck.service tools/hil/proxy-healthcheck.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now proxy-healthcheck.timer
journalctl -t bolty-proxy-health -f   # state transitions
```

Healthy = any non-52x/530/000 response (the app 4xx-ing a bare `/ln` proves
the origin is alive); DOWN is logged on every transition and on each check
that stays down.

## Role switching

The same stick can also run the esp32-ccid reader firmware (pcscd role).
`ccid-firmware-rs tools/switch_role.sh bolty|ccid` orchestrates the flip
(daemon vs pcscd, rebuild, flash, verification) — see
ccid-firmware-rs docs/role-switch.md. Lesson B13 in this repo covers the
control-line/tty-name traps that made switching flaky before.

## HIL Test Framework (2026-09-02)

Quick regression testing without LLM involvement — see root `Makefile`:

```bash
make test       # host unit tests (CI parity, no hardware)
make test-hil   # preflight + burn→lock→tap→gated-wipe→blank (3s, ACR only)
make difftest   # 66/66 APDU differential (10-20 min, role switch + both readers)
make test-all   # everything
```

Framework: `tools/hil/hil/` (cards.toml registry, preflight checks, role_guard
context manager). Tests: `tools/hil/tests/`. The card registry is the safety
contract — only listed UIDs with matching ops are touched. `test_burn_cycle.py`
at this level is superseded by `tests/test_burn_lock_wipe.py`.

## Troubleshooting

### Stick "frozen" (console unresponsive)
Two different failure modes with the same symptom:
- **Daemon-level** (heartbeats FRESH in ~/.bolty/console.log): restart the daemon
  ```bash
  sudo systemctl restart bolty-console
  ```
- **MFRC522-level** (heartbeats STALE or uid still empty after daemon restart):
  reflash cycle via role switch
  ```bash
  timeout 420 python3 -c "
  import sys; sys.path.insert(0, 'tools/hil/overnight')
  import role_switch
  r = role_switch.switch_to('ccid', results_dir='tools/hil/overnight/results/recovery')
  print(r.ok, r.detail)"
  timeout 420 python3 -c "
  import sys; sys.path.insert(0, 'tools/hil/overnight')
  import role_switch
  r = role_switch.switch_to('bolty', results_dir='tools/hil/overnight/results/recovery/restore')
  print(r.ok, r.detail)"
  ```

### labgrid-exporter blocking the shell
Never run labgrid-exporter interactively — it holds open network connections
and blocks the calling shell. It runs as a systemd service:
```bash
systemctl status labgrid-exporter
```

### Difftest timeout
The APDU differential takes 3-4 minutes through the GemPCTwin at 115200 baud.
If it times out, the role_guard context manager will have restored the stick
to bolty role (proven under interruption). Just re-run.
