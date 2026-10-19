# STM32 NFC frontend wiring plan — MFRC522 + PN532 (2026-10-19)

Planning only — no wiring done, no hardware procured. Extends
`docs/stm32-bringup-2026-10-19.md` (skeleton booted 2026-10-19) and
revives the June design in `docs/unified-board-config.md` (NfcBackend /
auto-detect) with a concrete hardware target: the shared F469I-DISCO.

Owner decision requested on: pin selection sign-off, module procurement,
and whether Option B lands on the F469 or the spare F746.

## Why two frontends

- **MFRC522 (Option A)** — bolty's primary PCD (same chip as the ESP32
  rig, I2C 0x28, `mfrc522-pcd` + `bolty-mfrc522` proven on the Atom).
  Cheapest software path: everything exists, only the HAL layer is new.
- **PN532 (Option B)** — revive the dormant crates (`pn532-transport`,
  `bolty-pn532`, added ~June, `Pn532Ops` made portable in 1625e0f, never
  had a bench target since the ESP32 rig standardized on MFRC522).
  PN532 adds ISO-DEP robustness + SAM/mifare family breadth and is the
  stepping stone to the auto-detect architecture the old plan wanted.
  Shared crate: ccid-firmware-rs also builds a PN532 backend (ESP32,
  SPI) — improvements flow both ways.

## Hardware inventory (bench truth, 2026-10-19)

- **No PN532 module exists anywhere on the bench** (full labgrid resource
  dump checked). **Procure: 1× PN532 v3 module** (DIP-switch
  I2C/SPI/HSU, 5V VIN w/ onboard LDO, 3V3 logic — STM32-direct
  compatible), ~€10.
- **MFRC522**: the bench's only module is wired into the `m5stick` Atom
  rig (I2C 0x28) — that rig runs nucula and is owner-gated; do NOT
  disturb. **Procure a second MFRC522 module** for the F469.
- Plus: dupont jumpers, optional 4.7k I2C pull-ups (modules usually
  carry them — verify before adding more).

## Board pin budget (F469I-DISCO, shared!)

Claimed pins today (verify before every wire; sources cited):

| Pins | Claimed by | Source |
|---|---|---|
| PA2, PA4, PG10, PC5, PC2 | ccid smartcard socket (USART2 ISO7816) | ccid-firmware-rs PINOUT.md |
| PA11, PA12 | USB OTG FS (ccid reader identity) | ccid-firmware-rs PINOUT.md |
| PB8, PB9 | onboard FT6X06 touch, I2C1 (display build) | vendor/stm32f469i-disc/src/touch.rs:49 |
| FMC/SDRAM, DSI, LTDC, SAI sets | onboard display/audio (display builds) | BSP sources + UM2171 |
| ST-LINK VCP (if02) | tied to a USART via solder bridges — check which before reusing it as our console | UM2171 |

The board is reflashed by THREE projects (ccid, micronuts wallet,
bolty/gm65 scanner). Any added wiring is permanent for all tenants:

- All wiring decisions end in a **conwrt-lab `lab.yaml` registry
  commit** (hardware state is that repo's domain) + a
  `PINOUT-nfc.md` here.
- Re-flash discipline per the ccid wedge table: `st-flash
  --connect-under-reset` only (their `stm32_flash.flash_f469` helper),
  never a bare `st-flash write`.

### Candidate pins (each needs the verification checklist before sign-off)

- **I2C for MFRC522 (A)**: I2C1 alt map **PB6/PB7** or **I2C2
  PB10/PB11** or **I2C3 (PA8/PC9 class)**. PB8/PB9 excluded (touch).
  PB10/PB11 risk: onboard audio codec may sit on I2C2 — check UM2171
  + one I2C scan with everything idle.
- **SPI for PN532 (B)**: **SPI1 PB3/PB4/PB5** (+ CS/IRQ/RST on free
  GPIOs) or **SPI2/SPI4 header-available sets**. PA5/PA6/PA7 also
  candidates if the Arduino header exposes them and no tenant claims
  them.
- **IRQ lines**: MFRC522 IRQ optional (polling); PN532 IRQ recommended.
- **Power**: both modules from the DISCO's 3V3 (MFRC522) / 5V VBUS
  rail → module LDO (PN532). Check current budget (PN532 peak ~100mA
  on field-on) against the bench rail.

Verification checklist per pin choice (do once, record in
PINOUT-nfc.md): UM2171 header availability; grep ccid + micronuts +
gm65 trees for the pin; BSP display-build pins; idle I2C scan; then
sign-off.

### Fallback host: the F746

The `stm32-f746` place is free (Cherry ST2XXX-F746, user USB unplugged).
Parking ONE frontend there avoids stacking wires on the shared F469 at
the cost of a `board-stm32f746` variant (memory.x: 1M flash; ccid
already maintains both boards — good precedent). Default recommendation:
both on the F469 (bolty owns the flash when running bolty), F746 kept as
escalation if pin contention gets ugly.

## Option A — MFRC522 on I2C (do first)

Software (all pieces exist; only the HAL layer is new):

1. **Add `stm32f4xx-hal`** (Amperstrand fork, rev `05d999d`, features
   `stm32f469` — same pin ccid uses) as a target-only dep of
   `bolty-stm32`. None exists today (the skeleton has no HAL).
2. RCC init on the DISCO's 8 MHz HSE (ccid main.rs is the reference);
   UART console candidate: the USART tied to the ST-LINK VCP — console
   without extra wires.
3. `I2c::new(...)` at 100 kHz on the chosen pins → first proof =
   address scan ACKs 0x28 (`mfrc522_pcd::DEFAULT_I2C_ADDRESS`).
4. `Mfrc522Transceiver::from_i2c(i2c, 0x28)` → read Version register
   (expect 0x91/0x92) → `Mfrc522Transport::activate` → ISO14443A poll.
5. Validation ladder (each step an RTT transcript, defmt now proven on
   this board): I2C scan → Version reg → REQA/wupA → NTAG424 activate →
   burn/wipe cycle against `tools/hil/cards.toml` rules → differential
   vs `ref-acr1252`.

## Option B — PN532 revival (second)

1. **Procure the module** (lead time is the critical path).
2. **Bus choice**: the `pn532` crate 0.5.0 is **SPI-only**
   (`msb-spi`; no i2c feature — checked registry source). Two sub-paths:
   - **B1 (recommended): SPI** — zero new driver code; wire
     SCK/MISO/MOSI/CS (+IRQ, RST), DIP per module silkscreen for SPI.
   - **B2 (later, architecture play): add an I2C interface to the pn532
     crate** (fork first, upstream later) so MFRC522 (0x28) + PN532
     (0x24) share ONE bus and the old doc's boot auto-detect
     (`NfcBackend` enum, `nfc-auto` feature) lands as designed.
3. Software:
   - `nfc-pn532 = ["dep:pn532-transport", "dep:bolty-pn532"]` feature
     in bolty-stm32 (per the unified-board-config feature table).
   - F469 constructor for `Pn532Device` (mirror the xtensa-gated one;
     the `Pn532Ops` trait is already portable). Integration spike:
     pn532 0.5 wants `Timer: CountDown<Time = Duration>` (nb-era trait)
     — confirm the hal fork's Timer satisfies it or write the small
     adapter.
   - `bolty-pn532` itself needs no changes — it is generic over
     `Pn532Ops` and already implements `ntag424::Transport`.
4. Validation ladder: GetFirmwareVersion (PN532 fw 1.6 expected) →
   SAM config → InListPassiveTarget TypeA → ISO-DEP APDU exchange →
   same NTAG424 burn/wipe + ACR differential as Option A.

## Sequencing

1. Owner: sign off pin picks (or request the verification checklist be
   run first), order both modules, decide F469-vs-F746 for B.
2. Wire A + software phase A1-A4 (one session once the module arrives;
   RTT transcript evidence per the bring-up doc's tooling notes).
3. Wire B1 + `nfc-pn532` (one session + one validation session).
4. Optional B2 (I2C unification + `nfc-auto` boot detect) as its own
   lane; ST25R95 stays parked (`docs/st25r95-plan.md`).

## Risks

- Pin collision with co-tenant firmware (mitigation: checklist +
  conwrt-lab registry + PINOUT-nfc.md).
- I2C bus loading/pull-up duplication (MFRC522 + PN532 + any onboard
  devices) — scope with B2 only.
- The e-h nb CountDown trait-version seam in the pn532 crate (spike
  first; worst case a 20-line adapter).
- Bench card-budget doctrine still applies to every validation burn
  (`tools/hil/cards.toml`, auth-attempt budgets in AGENTS.md).
