#!/usr/bin/env python3
"""Offline auth tests: AN12196 vectors + a full in-process handshake.

No pcscd needed — CI-safe. The in-process test mirrors the HOST side of
AuthenticateEV2First exactly as the ntag424 crate builds it (commands/
authenticate/aes.rs): Part 1 parse, RndB decrypt, Part 2 construction,
response verification, session derivation — then asserts BOTH sides
derived identical Kenc/Kmac (mutual auth, in software).

The live proof (bench-host only): bolty-cli try-key --key 00..00 against
the vpicc model over vpcd → "✅ Key accepted!" (2026-10-31, exchange log
in the PR). Requires BOLTY_SKIP_FFCA_RECONNECT=1 BOLTY_UID_OVERRIDE=…
(the reconnect desyncs the vpcd stream — stale ATR tail as SW).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytest.importorskip('Crypto', reason='pycryptodome: bench-host dep, not on CI runners')

sys.path.insert(0, str(Path(__file__).parent))

from vpicc_model_auth import (  # noqa: E402
    FACTORY_KEY, AuthEngine, _cbc_zero_iv_decrypt, _cbc_zero_iv_encrypt,
    _rot_left, derive_session,
)


def test_an12196_vectors():
    # Both NXP worked examples pinned by the crate's own suite tests.
    kx = b"\x00" * 16
    cases = [
        ("B98F4C50CF1C2E084FD150E33992B048",
         "91517975190DCEA6104948EFA3085C1B",
         "7A93D6571E4B180FCA6AC90C9A7488D4",
         "FC4AF159B62E549B5812394CAB1918CC"),
        ("13C5DB8A5930439FC3DEF9A4C675360F",
         "B9E2FC789B64BF237CCCAA20EC7E6E48",
         "1309C877509E5A215007FF0ED19CA564",
         "4C6626F5E72EA694202139295C7A7FC7"),
    ]
    for ra, rb, kenc, kmac in cases:
        e, m = derive_session(kx, bytes.fromhex(ra), bytes.fromhex(rb))
        assert e == bytes.fromhex(kenc), f"Kenc {ra[:8]}"
        assert m == bytes.fromhex(kmac), f"Kmac {ra[:8]}"


def test_full_handshake_in_process():
    """Host-mirror (crate semantics) ↔ AuthEngine, both sides check."""
    rnd_a = os.urandom(16)
    engine = AuthEngine(keys={0: FACTORY_KEY}, rnd_b=os.urandom(16))

    # Host Part 1: 90 71 00 00 05 <keyno> 03 00 00 00 00
    r1 = engine.answer(bytes.fromhex("9071000005000300000000"))
    assert r1[-2:] == b"\x91\xaf", f"part1 SW {r1[-2:].hex()}"
    rnd_b_enc = r1[:-2]
    assert len(rnd_b_enc) == 16
    rnd_b = _cbc_zero_iv_decrypt(FACTORY_KEY, rnd_b_enc)

    # Host Part 2: CBC(Kx, RndA || RndB_rot1)
    ct = _cbc_zero_iv_encrypt(
        FACTORY_KEY, rnd_a + _rot_left(rnd_b))
    part2 = bytes([0x90, 0xAF, 0x00, 0x00, 0x20]) + ct + b"\x00"
    r2 = engine.answer(part2)
    assert r2[-2:] == b"\x91\x00", f"part2 SW {r2[-2:].hex()} (DESfire OK)"
    resp = _cbc_zero_iv_decrypt(FACTORY_KEY, r2[:-2])
    ti, rnd_a_prime = resp[:4], resp[4:20]
    assert len(resp) == 32
    # rotate-right to recover RndA; must equal what we sent
    recovered = bytes([rnd_a_prime[15]]) + rnd_a_prime[:15]
    assert recovered == rnd_a, "RndA' mismatch — mutual auth broken"

    host_enc, host_mac = derive_session(FACTORY_KEY, rnd_a, rnd_b)
    assert engine.session is not None, "engine did not derive a session"
    card_enc, card_mac = engine.session
    assert host_enc == card_enc and host_mac == card_mac, \
        "session keys diverged between host mirror and card engine"


def test_wrong_rndb_rejected():
    engine = AuthEngine(keys={0: FACTORY_KEY}, rnd_b=os.urandom(16))
    r1 = engine.answer(bytes.fromhex("9071000005000300000000"))
    rnd_b = _cbc_zero_iv_decrypt(FACTORY_KEY, r1[:-2])
    tampered = bytes([rnd_b[0] ^ 1]) + rnd_b[1:]
    ct = _cbc_zero_iv_encrypt(FACTORY_KEY, os.urandom(16) + _rot_left(tampered))
    r2 = engine.answer(bytes([0x90, 0xAF, 0x00, 0x00, 0x20]) + ct + b"\x00")
    assert r2 == b"\x91\xae", f"expected 91AE auth-fail, got {r2.hex()}"


def _h_full_write(engine, data: bytes) -> bytes:
    """Host mirror of CommMode.FULL WriteData (crate write_data.rs)."""
    from vpicc_model_auth import AuthEngine as _E
    assert engine.session is not None
    kenc, kmac = engine.session
    ctr = engine.ctr
    ti = engine.ti
    # ISO 9797-1 method 2 padding
    padded = bytearray(data + b"\x80")
    while len(padded) % 16:
        padded.append(0)
    iv_block = bytearray(16)
    iv_block[0:2] = b"\xa5\x5a"
    iv_block[2:6] = ti
    iv_block[6:8] = ctr.to_bytes(2, "little")
    iv = _E and __import__("Crypto.Cipher.AES", fromlist=["AES"]).new(
        kenc, __import__("Crypto.Cipher.AES", fromlist=["AES"]).MODE_ECB
    ).encrypt(bytes(iv_block))
    from Crypto.Cipher import AES as _AES
    ct = _AES.new(kenc, _AES.MODE_CBC, iv=iv).encrypt(bytes(padded))
    header = bytes([2, 0, 0, 0]) + len(data).to_bytes(3, "little")  # file 2
    mac_full = __import__("vpicc_model_auth", fromlist=["_cmac"])._cmac(
        kmac, bytes([0x8D]) + ctr.to_bytes(2, "little") + ti + header + ct)
    mac_t = bytes(mac_full[2 * i + 1] for i in range(8))
    lc = 7 + len(ct) + 8
    return bytes([0x90, 0x8D, 0x00, 0x00, lc]) + header + ct + mac_t + b"\x00"


def test_secure_write_roundtrip():
    engine = AuthEngine(keys={0: FACTORY_KEY}, rnd_b=os.urandom(16))
    r1 = engine.answer(bytes.fromhex("9071000005000300000000"))
    assert r1[-2:] == b"\x91\xaf"
    rnd_b = _cbc_zero_iv_decrypt(FACTORY_KEY, r1[:-2])
    rnd_a = os.urandom(16)
    ct = _cbc_zero_iv_encrypt(FACTORY_KEY, rnd_a + _rot_left(rnd_b))
    r2 = engine.answer(bytes([0x90, 0xAF, 0x00, 0x00, 0x20]) + ct + b"\x00")
    assert r2[-2:] == b"\x91\x00"
    payload = bytes.fromhex("deadbeef") * 3  # 12B -> 16B padded
    apdu = _h_full_write(engine, payload)
    r = engine.answer(apdu)
    assert r[-2:] == b"\x91\x00", f"write SW {r[-2:].hex()}"
    assert len(r) == 10, "response must be MACt(8) + SW"
    # engine applied the write and advanced the counter
    assert engine.ctr == 1
    fno, plain = engine.last_written
    assert fno == 2 and plain[:len(payload)] == payload
    # second write with a stale (replayed) counter must fail integrity
    apdu2 = _h_full_write(engine, payload)  # engine.ctr now 1; mirror uses 1
    # forge replay of the FIRST apdu (ctr 0 mac) -> engine at ctr 1 -> 911E
    r2 = engine.answer(apdu)
    assert r2 == b"\x91\x1e", f"replay must 911E, got {r2.hex()}"
    # fresh correctly-counter'd write succeeds again
    r3 = engine.answer(apdu2)
    assert r3[-2:] == b"\x91\x00" and engine.ctr == 2
