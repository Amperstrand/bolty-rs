# PINOUT-nfc — NFC frontend wiring for the F469I-DISCO (bolty-stm32)

Companion to `docs/stm32-nfc-frontend-plan.md`. Status: PROPOSED —
no wiring done yet. Every claim below was verified against in-tree
sources on 2026-10-19 (see the checklist). Wiring changes must also land
in the conwrt-lab `lab.yaml` registry.

## Claimed pins on this board (do not use)

| Pins | Claimed by | Evidence |
|---|---|---|
| PA2, PA4 | USART2 smartcard I/O + CLK (ccid socket) | ccid-firmware-rs PINOUT.md |
| PG10, PC5, PC2 | smartcard RST / PWR / PRES | ccid-firmware-rs PINOUT.md |
| PA11, PA12 | USB OTG FS (reader identity) | ccid-firmware-rs PINOUT.md |
| PB8, PB9 | onboard FT6X06 touch (I2C1 primary map) | vendor/stm32f469i-disc/src/touch.rs:49 |
| PC8, PC9 (…) | SDIO in display builds (PC9 confirmed as SDIO D1) | vendor BSP sdio.rs:55 |
| FMC/SDRAM, DSI/LTDC sets | onboard display (display builds) | vendor BSP sdram.rs + #193 |

## Proposal

### Option A — MFRC522 on I2C1 alt map (PB6/PB7)

| Signal | MCU pin | AF | Notes |
|---|---|---|---|
| SCL | PB6 | 4 | no in-tree claim found |
| SDA | PB7 | 4 | no in-tree claim found |
| 3V3 / GND | — | — | module has onboard pull-ups — verify before adding more |
| (IRQ) | — | — | optional; polling is fine for burn-cycle work |

Firmware already implements this mapping + a boot bus scan
(`board::init` in apps/bolty-stm32/src/main.rs, feature
`board-stm32f4-disco`). Expected device address:
`mfrc522_pcd::DEFAULT_I2C_ADDRESS` = 0x28.

Why not I2C2 (PB10/PB11): possible onboard audio codec on I2C2
(UM2171 — NOT yet verified from primary sources); I2C1 alt map has
zero in-tree conflicts. The boot scan will empirically confirm the
bus is quiet before the module is wired.

### Option B — PN532 v3 module on SPI1 (PB3/PB4/PB5)

| Signal | MCU pin | AF | Notes |
|---|---|---|---|
| SCK | PB3 | 5 | no in-tree claim found |
| MISO | PB4 | 5 | no in-tree claim found |
| MOSI | PB5 | 5 | no in-tree claim found |
| CS | PB0 or PA15 (TBD at wiring) | GPIO out | PA15 usable with SWD-only debug |
| IRQ | PB1 or PB2≠ (TBD) | GPIO in | PB2 is BOOT1 — avoid |
| RST | PA15/PB0 class (TBD) | GPIO out | pick distinct from CS/IRQ |
| 5V VIN / GND | — | — | module LDO makes 3V3; logic is 3V3 — direct |
| DIP switches | SEL0/SEL1 per silkscreen = SPI | — | verify per module revision |

The `pn532` crate 0.5 is SPI-only (`msb-spi`) — this wiring matches the
existing `pn532-transport` code with zero driver changes. The
`nfc-pn532` feature now cross-compiles for thumbv7em (spike verified
2026-10-19).

## Console (later)

USART1 PA9/PA10 is the likely ST-LINK VCP path on this DISCO — verify
the solder-bridge state (UM2171) before relying on it; defmt RTT is the
console until then.

## Checklist (what was checked, 2026-10-19)

- [x] ccid-firmware-rs tree + vendor BSP greps for all candidate pins
      (only PC9 hit — SDIO, excluded)
- [x] micronuts tree: ESP32-only, no F469 pin claims
- [x] gm65 scanner: its F469 is the OTHER board (ai-legion-small,
      `ai-legion-small-microfips/stm32-stlink` resource) — not ours
- [x] `pn532` crate 0.5.0 features: `msb-spi`, `std` only — no I2C
- [x] **PB6/PB7 bus scan on hardware (2026-10-19 evening cycle)**: the
      NFC-prep build (ELF 928dfe5b…) boots with clocks + I2C1 init and
      scans 0x01..0x7F — ZERO devices answer. The bus is electrically
      quiet; safe to land the MFRC522 on it (evidence:
      /tmp/opencode/bolty-stm32-bringup/transcript-nfc-prep.txt).
- [x] HAL fork rev 05d999d APIs: `RCC.freeze(Config)`, `GPIOx.split(&mut rcc)`,
      `I2c::new(i2c, (scl, sda), freq, &mut rcc)` (BSP touch.rs pattern)
- [ ] UM2171 header exposure of PB3-PB7 / PB0 / PA15 (check at wiring time)
- [ ] Onboard I2C2 occupancy (audio codec) — the boot scan answers this
      empirically if we ever move to a shared-bus design (plan B2)
- [ ] ST-LINK VCP bridge state (console decision)

## Coordination contract

- The board is reflashed by ccid (smartcard/display) and bolty; flash
  only via `st-flash --connect-under-reset` (wedge table in ccid
  AGENTS.md); never a bare `st-flash write`.
- After physical wiring: conwrt-lab `lab.yaml` commit + update this
  file with as-built truth.
