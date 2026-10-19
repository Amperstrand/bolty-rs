# cortex-m-rt `-Tlink.x`: why the workspace config exists, and when we can slim it down

Context: the STM32 lane hit this during #111 (fixed in PR #113); this note
records the full picture so the wiring is never "simplified away" and the
failure mode is recognized on sight. Verified against cortex-m-rt 0.7.7 /
rustc 1.99.0 / thumbv7em-none-eabihf (2026-10-19).

## The wiring is required usage, not a workaround

`cortex-m-rt` does not — and never did — pass its own linker script to the
linker. In every release checked (0.5.6, 0.6.13, 0.7.7) its `build.rs`
only emits `cargo:rustc-link-search` so the linker can *find* `link.x`;
passing `-Tlink.x` is the user's job. We do it in the workspace
`.cargo/config.toml`:

```toml
[target.'cfg(all(target_arch = "arm", target_os = "none"))']
rustflags = ["-C", "link-arg=-Tlink.x"]
```

(The cfg gate keeps host builds untouched. The same pattern is used by
knurling-rs/app-template, the successor of the archived cortex-m-quickstart.)

> Historical accuracy: the PR #113 bullet "cortex-m-rt 0.7 no longer
> passes its link script itself" overstated a regression — there was none
> to regress from. Same fix either way.

## Why we carry extra vigilance

Omitting the flag is **not** a build error. `cargo build` exits 0 and the
only diagnostic is easy to dismiss:

```
warning: linker stderr: rust-lld: cannot find entry symbol _start; not setting start address
```

The ELF is a hosted-style binary that cannot run on the device:

| `cargo build` | without `-Tlink.x` | with `-Tlink.x` |
|---|---|---|
| exit code | 0 | 0 |
| only diagnostic | the `rust-lld` `_start` warning above | none |
| entry point | `0x0` | `0x08000401` (flash) |
| loadable sections | none (`.debug_*` only) | `.vector_table @ 0x08000000`, `.text`, `.data`, `.bss` |

Our #111 hit: a ~596-byte ELF that naturally refused to flash. Post-fix
release build: 197,808-byte ELF, `.vector_table @ 0x08000000`, entry
`0x08000401`.

Compensating controls while the failure stays silent upstream:

- the comment block above the `[target.'cfg(...)']` table in
  `.cargo/config.toml`,
- the `stm32-check.yml` release-build lane (a missing `.vector_table` in
  CI output is an immediate red flag),
- this note.

Upstream status (2026-10-19): rust-embedded/cortex-m issue #471 (open
since 2023-02-17) describes exactly this; a maintainer sketched a
build-script warning in the comments; nothing has landed through 0.7.7.
Deliberate decision: we do not comment or PR upstream — the fix on our
side is proven, and the knowledge lives here.

## What would have to change upstream for us to slim this down

Exit criterion: a cortex-m-rt release that warns at build time when no
linker script is detected (#471 resolved). When that ships, the failure
stops being silent and the compensating comment/note can shrink to a
pointer — **the `rustflags` wiring itself stays forever** (it is required
usage, not a workaround).

For the record, we hold a validated design should policy ever change: a
~25-line `build.rs` warning gated on `CARGO_CFG_TARGET_OS == "none"`
scanning `CARGO_ENCODED_RUSTFLAGS` for `link-arg=-T…`. Verified end to
end: config-table/cfg-gated/`RUSTFLAGS` wiring is correctly detected
(verified working on all three channels), only scripts passed from the
user's own build script or a linker wrapper are invisible (the warning
text would tell those users to ignore it). Evidence lives in the
boltcard2 lane packet (`upstream/cortex-m-rt/`).

Monitoring trigger: watch cortex-m-rt releases/CHANGELOG for a
missing-linker-script warning.
