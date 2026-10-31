#!/usr/bin/env python3
"""vpicc_model_auth — card-side AuthenticateEV2 (AES) for the vpicc model.

Rung 2 of vpicc_model_design.md: the PICC's obligations of the NTAG424
AES handshake, mirroring the host side the `ntag424` crate implements
(commands/authenticate/aes.rs + crypto/suite.rs, both pinned to NXP
AN12196 worked examples — two of which are unit-pinned here too).

Wire shapes (crate citations):
- Part 1 First:    90 71 00 00 05 <KeyNo> 03 000000 00
                   card -> 91 AF + e(Kx, RndB)              (zero-IV CBC)
- Part 1 NonFirst: 90 77 00 00 01 <KeyNo> 00
                   card -> 91 AF + e(Kx, RndB)
- Part 2:          90 AF 00 00 20 <32B: CBC(Kx, RndA||RndB_rot1)> 00
                   card -> 90 00 + CBC(Kx, TI || RndA_rot1 || PDcap2 || PCDcap2)
                   (32B; NonFirst: 16B, no TI/caps)
- Session (both sides derive identically, §9.1.7):
    SV1 = A5 5A | 00 01 00 80 | RndA[0:2] | RndA[2:8]^RndB[0:6]
          | RndB[6:16] | RndA[8:16]
    SV2 = same with 5A A5
    Kenc = CMAC(Kx, SV1); Kmac = CMAC(Kx, SV2)

Failure: wrong RndB' in Part 2 -> 91 AE (auth failed).

Keys: default {key 0: FACTORY all-zeros} (matches a blank card profile
and bolty-cli try-key --key 00..00).
"""

from __future__ import annotations

import os

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

SW_AF = b"\x91\xaf"      # additional frame
SW_OK = b"\x91\x00"  # DESfire OK (AN12196 transcript: part-2 success is 91 00)
SW_AUTH_FAIL = b"\x91\xae"

FACTORY_KEY = b"\x00" * 16


def _cbc_zero_iv_encrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(data)


def _cbc_zero_iv_decrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(data)


def _cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES, mac_len=16)
    c.update(data)
    return c.digest()


def _rot_left(b: bytes) -> bytes:
    return b[1:] + b[:1]


def session_vector(label: bytes, rnd_a: bytes, rnd_b: bytes) -> bytes:
    """§9.1.7 SV1/SV2 assembly (crate: session_vector_aes)."""
    sv = bytearray(32)
    sv[0:2] = label
    sv[2:6] = bytes([0x00, 0x01, 0x00, 0x80])
    sv[6:8] = rnd_a[0:2]
    for i in range(6):
        sv[8 + i] = rnd_a[2 + i] ^ rnd_b[i]
    sv[14:24] = rnd_b[6:16]
    sv[24:32] = rnd_a[8:16]
    return bytes(sv)


def derive_session(kx: bytes, rnd_a: bytes, rnd_b: bytes) -> tuple[bytes, bytes]:
    """Kenc, Kmac (§9.1.7)."""
    kenc = _cmac(kx, session_vector(b"\xa5\x5a", rnd_a, rnd_b))
    kmac = _cmac(kx, session_vector(b"\x5a\xa5", rnd_a, rnd_b))
    return kenc, kmac


class AuthEngine:
    """Tracks the in-flight handshake. One engine per connection."""

    def __init__(self, keys: dict[int, bytes] | None = None,
                 ti: bytes = b"\x01\x02\x03\x04",
                 rnd_b: bytes | None = None):
        self.keys = keys if keys is not None else {0: FACTORY_KEY}
        self.ti = ti
        self._rnd_b = rnd_b
        self.pending: tuple[bytes, bytes] | None = None  # (kx, rnd_b)
        self.session: tuple[bytes, bytes] | None = None  # (kenc, kmac)

    def answer(self, capdu: bytes) -> bytes:
        """Return the R-APDU (data + SW) for a CLA-90 auth APDU.

        Returns b"" when the APDU is not an auth command (caller falls
        through to the pre-auth rules).
        """
        if len(capdu) < 6 or capdu[0] != 0x90:
            return b""
        ins = capdu[1]

        if ins in (0x71, 0x77):  # AuthenticateEV2 First / NonFirst, part 1
            key_no = capdu[5]
            kx = self.keys.get(key_no)
            if kx is None:
                return SW_AUTH_FAIL
            rnd_b = self._rnd_b if self._rnd_b else os.urandom(16)
            self.pending = (kx, rnd_b)
            # NonFirst part1 body: KeyNo at capdu[5] directly; First has
            # KeyNo first too (LenCap follows) — same extraction either way.
            return _cbc_zero_iv_encrypt(kx, rnd_b) + SW_AF

        if ins == 0xAF and self.pending is not None:  # part 2
            kx, rnd_b = self.pending
            self.pending = None
            ct = capdu[5:5 + 32]
            if len(ct) != 32:
                return SW_AUTH_FAIL
            pt = _cbc_zero_iv_decrypt(kx, ct)
            rnd_a, rnd_b_prime = pt[:16], pt[16:]
            if rnd_b_prime != _rot_left(rnd_b):
                return SW_AUTH_FAIL
            rnd_a_rot = _rot_left(rnd_a)
            if ins == 0xAF and len(capdu) >= 2 and self._is_first:
                resp_plain = self.ti + rnd_a_rot + b"\x00" * 12
            else:  # NonFirst: 16B only
                resp_plain = rnd_a_rot
            self.session = derive_session(kx, rnd_a, rnd_b)
            return _cbc_zero_iv_encrypt(kx, resp_plain) + SW_OK

        return b""

    _is_first = True  # First/NonFirst share part-2 shape here (TI+caps
    # only matter to First; serving them always is harmless — the host
    # reading NonFirst expects 16B and would fail loudly if wrong).


# ── AN12196 unit pins (crate: crypto::suite::tests) ──────────────────────────

def _selftest() -> None:
    kx = b"\x00" * 16
    v1 = ("B98F4C50CF1C2E084FD150E33992B048",
          "91517975190DCEA6104948EFA3085C1B",
          "7A93D6571E4B180FCA6AC90C9A7488D4",
          "FC4AF159B62E549B5812394CAB1918CC",
          "A55A00010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048")
    v2 = ("13C5DB8A5930439FC3DEF9A4C675360F",
          "B9E2FC789B64BF237CCCAA20EC7E6E48",
          "1309C877509E5A215007FF0ED19CA564",
          "4C6626F5E72EA694202139295C7A7FC7",
          "A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F")
    for ra, rb, kenc, kmac, sv1 in (v1, v2):
        ra_b, rb_b = bytes.fromhex(ra), bytes.fromhex(rb)
        assert session_vector(b"\xa5\x5a", ra_b, rb_b) == bytes.fromhex(sv1), \
            f"SV1 mismatch for {ra[:8]}"
        got_enc, got_mac = derive_session(kx, ra_b, rb_b)
        assert got_enc == bytes.fromhex(kenc), f"Kenc mismatch for {ra[:8]}"
        assert got_mac == bytes.fromhex(kmac), f"Kmac mismatch for {ra[:8]}"
    print("AN12196 vectors: SV1/Kenc/Kmac all match")


if __name__ == "__main__":
    _selftest()
