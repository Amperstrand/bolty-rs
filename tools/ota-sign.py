#!/usr/bin/env python3
"""OTA firmware signing tool for bolty-rs.

Usage:
  # Generate a new Ed25519 keypair
  python3 ota-sign.py keygen --privkey ota_key.pem

  # Show the public key hex (for 'provision-ota-key' serial command)
  python3 ota-sign.py pubkey --privkey ota_key.pem

  # Sign a firmware binary (outputs 128-char hex signature)
  python3 ota-sign.py sign --privkey ota_key.pem --firmware target/xtensa-esp32-espidf/release/bolty-esp32.bin

Flow:
  1. keygen → save private key
  2. pubkey → copy hex to 'provision-ota-key <hex>' via USB serial
  3. sign → copy signature to 'ota <url> <signature_hex>' via serial/REST
"""
import argparse
import hashlib
import sys
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def cmd_keygen(args):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    with open(args.privkey, "wb") as f:
        f.write(pem)
    os.chmod(args.privkey, 0o600)

    pub = key.public_key()
    pub_bytes = pub.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    print(f"Private key saved to {args.privkey}")
    print(f"Public key (hex):  {pub_bytes.hex()}")
    print(f"Public key (hex):  {pub_bytes.hex()}")
    print()
    print("Run on device via USB serial:")
    print(f"  provision-ota-key {pub_bytes.hex()}")


def cmd_pubkey(args):
    with open(args.privkey, "rb") as f:
        priv = load_pem_private_key(f.read(), password=None)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    print(pub_bytes.hex())


def cmd_sign(args):
    with open(args.privkey, "rb") as f:
        priv = load_pem_private_key(f.read(), password=None)

    with open(args.firmware, "rb") as f:
        firmware = f.read()

    fw_hash = hashlib.sha256(firmware).digest()
    signature = priv.sign(fw_hash)

    print(f"Firmware: {args.firmware} ({len(firmware)} bytes)")
    print(f"SHA-256:  {fw_hash.hex()}")
    print(f"Signature: {signature.hex()}")
    print()
    print("Run on device via serial/REST:")
    print(f"  ota {args.url} {signature.hex()}")


def cmd_verify(args):
    with open(args.privkey, "rb") as f:
        priv = load_pem_private_key(f.read(), password=None)
    pub = priv.public_key()

    sig = bytes.fromhex(args.signature)
    if len(sig) != 64:
        print("ERROR: signature must be 128 hex chars (64 bytes)", file=sys.stderr)
        sys.exit(1)

    with open(args.firmware, "rb") as f:
        firmware = f.read()

    fw_hash = hashlib.sha256(firmware).digest()
    try:
        pub.verify(sig, fw_hash)
        print("✅ Signature VALID")
    except InvalidSignature:
        print("❌ Signature INVALID")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="OTA firmware signing tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate Ed25519 keypair")
    p_keygen.add_argument("--privkey", default="ota_key.pem")
    p_keygen.set_defaults(func=cmd_keygen)

    p_pubkey = sub.add_parser("pubkey", help="Print public key hex")
    p_pubkey.add_argument("--privkey", default="ota_key.pem")
    p_pubkey.set_defaults(func=cmd_pubkey)

    p_sign = sub.add_parser("sign", help="Sign firmware binary")
    p_sign.add_argument("--privkey", default="ota_key.pem")
    p_sign.add_argument("--firmware", required=True)
    p_sign.add_argument("--url", default="https://example.com/firmware.bin")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify signature (for testing)")
    p_verify.add_argument("--privkey", default="ota_key.pem")
    p_verify.add_argument("--firmware", required=True)
    p_verify.add_argument("--signature", required=True)
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
