#!/usr/bin/env python3
"""Extract flash-region artifacts from the prebuilt merged images.

Both remaining reflash-path improvements consume split artifacts:

- bolty-rs #68 (WiFi/NVS survival): flash ONLY the partition table
  (0x8000) + app partition, leaving NVS (0x9000) and phy_init (0xF000)
  untouched — WiFi creds, cert, and boot counter survive role switches.
- bolty-rs #76 (OTA-slot role switching): dual-slot provisioning needs
  each role's app binary as a standalone artifact.

Reads the merged bins + MANIFEST.json from the images dir (verifying the
merged sha256s first), extracts the partition table and every app
partition, sanity-checks magic bytes, and writes <role>-pt.bin /
<role>-<part>.bin plus SPLIT_MANIFEST.json with sha256s. No hardware
touched — run any time after images are built.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

PT_OFFSET = 0x8000
PT_MAX_ENTRIES = 32
ESP_IMAGE_MAGIC = 0xE9
OTADATA_OFFSET = 0x10000


def _esp_rom_crc32_le(crc: int, buf: bytes) -> int:
    """Exact esp_rom_crc32_le per IDF components/esp_rom/linux/esp_rom_crc.c:
    invert-in, reflected table loop, invert-out — NOT plain zlib.crc32 and
    NOT zlib^0xFFFFFFFF (both empirically rejected by the bootloader)."""
    crc ^= 0xFFFFFFFF
    for b in buf:
        crc = _CRC32_LE_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
        crc &= 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


_CRC32_LE_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC32_LE_TABLE.append(_c)


def build_otadata_entry_ota0() -> bytes:
    """A minimal valid esp_ota_select_entry_t selecting ota_0 (32 bytes).

    Layout (ESP-IDF esp_flash_partitions.h): ota_seq u32 | seq_label[20] |
    ota_state u32 | crc u32. The bootloader validates crc == CRC32 of the
    ota_seq field ONLY (bootloader_common_ota_select_crc: ROM LE CRC-32 of
    the 4 seq bytes), and picks slot (ota_seq - 1) % ota_app_count — seq 1
    with our single ota_0 slot selects it. ota_state 0 = ESP_OTA_IMG_VALID.
    With both otadata sectors erased the bootloader falls back to factory —
    that is the bolty direction of the flip."""
    seq = struct.pack("<I", 1)
    label = b"bolty-rig-flip".ljust(20, b"\x00")
    state = struct.pack("<I", 0)
    crc = struct.pack("<I", _esp_rom_crc32_le(0xFFFFFFFF, seq))
    return seq + label + state + crc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_partition_table(image: bytes) -> list[dict]:
    entries = []
    for i in range(PT_MAX_ENTRIES):
        e = image[PT_OFFSET + i * 32: PT_OFFSET + (i + 1) * 32]
        if e[:2] != b"\xaa\x50":
            break
        entries.append({
            "name": e[12:28].rstrip(b"\x00").decode(),
            "type": e[2],
            "subtype": e[3],
            "offset": struct.unpack("<I", e[4:8])[0],
            "size": struct.unpack("<I", e[8:12])[0],
        })
    if not entries:
        raise ValueError("partition table at 0x8000 has no valid entries")
    return entries


def split_image(images_dir: Path, merged: Path, role: str) -> dict:
    parts = parse_partition_table(merged.read_bytes())
    out = {"partition_table_entries": parts, "artifacts": {}}

    pt_artifact = images_dir / f"{role}-pt.bin"
    pt_artifact.write_bytes(merged.read_bytes()[PT_OFFSET:PT_OFFSET + 0x1000])
    out["artifacts"]["pt"] = {
        "file": pt_artifact.name, "offset": PT_OFFSET,
        "sha256": sha256_file(pt_artifact),
    }

    for p in parts:
        if p["type"] != 0:  # 0 = app partitions
            continue
        region = merged.read_bytes()[p["offset"]:p["offset"] + p["size"]]
        if not region or region[0] == 0xFF:
            # Blank slot (e.g. ota_0 in a factory-only merged image) —
            # record as empty; #76 provisioning fills it from the other
            # role's factory artifact.
            out["artifacts"][p["name"]] = {
                "file": None, "offset": p["offset"], "size": p["size"],
                "empty": True,
            }
            continue
        if region[0] != ESP_IMAGE_MAGIC:
            raise ValueError(
                f"{role} app partition {p['name']} @ {p['offset']:#x} "
                "does not start with the ESP image magic 0xE9"
            )
        artifact = images_dir / f"{role}-{p['name']}.bin"
        artifact.write_bytes(region)
        out["artifacts"][p["name"]] = {
            "file": artifact.name, "offset": p["offset"], "size": p["size"],
            "sha256": sha256_file(artifact),
        }
    return out


def main(argv: list[str]) -> int:
    images_dir = Path(argv[1]).resolve() if len(argv) > 1 else (
        Path(__file__).resolve().parent / "results" / "images"
    )
    manifest_path = images_dir / "MANIFEST.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())

    for role, merged_name, key in (
        ("bolty", "bolty-merged.bin", "bolty_merged_sha256"),
        ("ccid", "esp32-ccid-merged.bin", "ccid_merged_sha256"),
    ):
        merged = images_dir / merged_name
        if not merged.exists():
            print(f"ERROR: {merged} not found", file=sys.stderr)
            return 1
        actual = sha256_file(merged)
        if actual != manifest[key]:
            print(
                f"ERROR: {merged_name} sha256 mismatch vs MANIFEST.json "
                f"(expected {manifest[key][:16]}…, got {actual[:16]}…) — "
                "rebuild the images before splitting",
                file=sys.stderr,
            )
            return 1

    split_manifest = {"source_manifest": manifest_path.name, "roles": {}}
    for role, merged_name, _ in (
        ("bolty", "bolty-merged.bin", None),
        ("ccid", "esp32-ccid-merged.bin", None),
    ):
        split_manifest["roles"][role] = split_image(images_dir, images_dir / merged_name, role)
        arts = split_manifest["roles"][role]["artifacts"]
        print(f"{role}: " + ", ".join(
            f"{name}→{a['file']}" for name, a in arts.items()
        ))

    otadata = images_dir / "otadata-ota0.bin"
    otadata.write_bytes(build_otadata_entry_ota0())
    split_manifest["otadata_ota0"] = {
        "file": otadata.name, "offset": OTADATA_OFFSET,
        "sha256": sha256_file(otadata),
    }
    print(f"otadata: {otadata.name} (entry selecting ota_0, seq=1 VALID)")

    out_path = images_dir / "SPLIT_MANIFEST.json"
    out_path.write_text(json.dumps(split_manifest, indent=2) + "\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
