from __future__ import annotations

from typing import Optional, Tuple

try:
    import numpy as np
    from numba import njit
except Exception:  # pragma: no cover
    np = None
    njit = None


# SHA256 constants
_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

_H0 = (
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
)


def available() -> bool:
    return (np is not None) and (njit is not None)


if available():
    import numpy as _np

    @_np.vectorize
    def _u32(x):  # pragma: no cover
        return _np.uint32(x)

    @njit(cache=True)
    def _rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @njit(cache=True)
    def _ch(x, y, z):
        return (x & y) ^ ((~x) & z)

    @njit(cache=True)
    def _maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    @njit(cache=True)
    def _bsig0(x):
        return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

    @njit(cache=True)
    def _bsig1(x):
        return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

    @njit(cache=True)
    def _ssig0(x):
        return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)

    @njit(cache=True)
    def _ssig1(x):
        return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)

    @njit(cache=True)
    def _load_u32_be(b0, b1, b2, b3):
        return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xFFFFFFFF

    @njit(cache=True)
    def _compress(state, block64):
        # state: uint32[8], block64: uint8[64]
        W = _np.zeros(64, dtype=_np.uint32)

        # first 16 words
        for i in range(16):
            j = 4 * i
            W[i] = _load_u32_be(block64[j], block64[j + 1], block64[j + 2], block64[j + 3])

        for i in range(16, 64):
            W[i] = (W[i - 16] + _ssig0(W[i - 15]) + W[i - 7] + _ssig1(W[i - 2])) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

        for i in range(64):
            t1 = (h + _bsig1(e) + _ch(e, f, g) + _K[i] + W[i]) & 0xFFFFFFFF
            t2 = (_bsig0(a) + _maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        state[0] = (state[0] + a) & 0xFFFFFFFF
        state[1] = (state[1] + b) & 0xFFFFFFFF
        state[2] = (state[2] + c) & 0xFFFFFFFF
        state[3] = (state[3] + d) & 0xFFFFFFFF
        state[4] = (state[4] + e) & 0xFFFFFFFF
        state[5] = (state[5] + f) & 0xFFFFFFFF
        state[6] = (state[6] + g) & 0xFFFFFFFF
        state[7] = (state[7] + h) & 0xFFFFFFFF

    @njit(cache=True)
    def _sha256_midstate(block0_64):
        st = _np.array(_H0, dtype=_np.uint32)
        _compress(st, block0_64)
        return st

    @njit(cache=True)
    def _sha256_from_state_two_blocks(state_after_block0, block1_64, out32):
        st = state_after_block0.copy()
        _compress(st, block1_64)
        # write digest big-endian bytes
        for i in range(8):
            w = st[i]
            out32[4*i + 0] = (w >> 24) & 0xFF
            out32[4*i + 1] = (w >> 16) & 0xFF
            out32[4*i + 2] = (w >> 8) & 0xFF
            out32[4*i + 3] = w & 0xFF

    @njit(cache=True)
    def _sha256_one_block(msg_bytes, msg_len_bytes, out32):
        # msg_bytes length <= 64; build padded 64-byte block
        block = _np.zeros(64, dtype=_np.uint8)
        for i in range(msg_len_bytes):
            block[i] = msg_bytes[i]
        block[msg_len_bytes] = 0x80
        bitlen = msg_len_bytes * 8
        # length in last 8 bytes big-endian
        block[63] = bitlen & 0xFF
        block[62] = (bitlen >> 8) & 0xFF
        block[61] = (bitlen >> 16) & 0xFF
        block[60] = (bitlen >> 24) & 0xFF
        # upper 4 length bytes are zero for msg_len <= 55
        st = _np.array(_H0, dtype=_np.uint32)
        _compress(st, block)
        for i in range(8):
            w = st[i]
            out32[4*i + 0] = (w >> 24) & 0xFF
            out32[4*i + 1] = (w >> 16) & 0xFF
            out32[4*i + 2] = (w >> 8) & 0xFF
            out32[4*i + 3] = w & 0xFF

    @njit(cache=True)
    def _cmp_hash_leq_target(hash32, target32_be):
        # Compare hash as big-endian integer <= target big-endian integer.
        # Compare 32 bytes lexicographically.
        for i in range(32):
            hb = hash32[i]
            tb = target32_be[i]
            if hb < tb:
                return True
            if hb > tb:
                return False
        return True  # equal

    @njit(cache=True)
    def find_nonce_sha256d_midstate(header76, start_nonce, count, target32_be):
        # header76: uint8[76]
        # Build block0 = first 64 bytes (constant)
        block0 = _np.empty(64, dtype=_np.uint8)
        for i in range(64):
            block0[i] = header76[i]
        mid = _sha256_midstate(block0)

        # Prepare constant portion of block1: bytes 64..76 (12 bytes) are constant,
        # bytes 76..80 are nonce (4 bytes, little-endian),
        # then padding for 80-byte message:
        # block1 layout:
        # [16 bytes msg tail][0x80][zeros...][64-bit length=640 bits]
        # total 64 bytes.
        const_tail12 = _np.empty(12, dtype=_np.uint8)
        for i in range(12):
            const_tail12[i] = header76[64 + i]

        block1 = _np.zeros(64, dtype=_np.uint8)
        # first 12 bytes fixed
        for i in range(12):
            block1[i] = const_tail12[i]
        # bytes 12..15 will be nonce bytes
        # padding
        block1[16] = 0x80
        # length = 80*8 = 640 bits in last 8 bytes big-endian
        bitlen = 80 * 8
        block1[63] = bitlen & 0xFF
        block1[62] = (bitlen >> 8) & 0xFF
        block1[61] = (bitlen >> 16) & 0xFF
        block1[60] = (bitlen >> 24) & 0xFF
        # upper length bytes remain zero

        hash1 = _np.empty(32, dtype=_np.uint8)
        hash2 = _np.empty(32, dtype=_np.uint8)

        nonce = start_nonce & 0xFFFFFFFF
        for _ in range(count):
            # nonce little-endian into block1[12..16)
            block1[12] = nonce & 0xFF
            block1[13] = (nonce >> 8) & 0xFF
            block1[14] = (nonce >> 16) & 0xFF
            block1[15] = (nonce >> 24) & 0xFF

            _sha256_from_state_two_blocks(mid, block1, hash1)
            _sha256_one_block(hash1, 32, hash2)

            if _cmp_hash_leq_target(hash2, target32_be):
                return nonce

            nonce = (nonce + 1) & 0xFFFFFFFF

        return -1


def _target_int_to_be_bytes32(target_int: int) -> "np.ndarray":
    b = int(target_int).to_bytes(32, "big")
    return np.frombuffer(b, dtype=np.uint8).copy()


def find_share_bounded_numba(header76: bytes, target_int: int, start_nonce: int, count: int) -> Optional[int]:
    """
    Returns nonce if found, else None.
    """
    if not available():
        raise RuntimeError("numba/numpy not available")

    if not isinstance(header76, (bytes, bytearray)) or len(header76) != 76:
        raise ValueError("header76 must be 76 bytes")
    if count <= 0:
        return None

    h = np.frombuffer(bytes(header76), dtype=np.uint8)
    tgt = _target_int_to_be_bytes32(int(target_int))
    n = find_nonce_sha256d_midstate(h, start_nonce & 0xFFFFFFFF, int(count), tgt)
    return None if int(n) < 0 else int(n)
else:
    def find_share_bounded_numba(*args, **kwargs):  # type: ignore
        raise RuntimeError("numba/numpy not available")
