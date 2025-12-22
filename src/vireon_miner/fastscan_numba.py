from __future__ import annotations

from typing import Optional

_HAS_NUMBA = False
np = None
njit = None

try:
    import numpy as np  # type: ignore
    from numba import njit  # type: ignore

    _HAS_NUMBA = True
except Exception:
    _HAS_NUMBA = False


def available() -> bool:
    return _HAS_NUMBA


# ---------- Pure-python helpers (safe even without numba) ----------

_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

_SHA256_H0 = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)


def _target_int_to_be_u8(target_int: int) -> "np.ndarray":
    # target is a 256-bit integer; represent as big-endian bytes
    b = int(target_int).to_bytes(32, "big", signed=False)
    return np.frombuffer(b, dtype=np.uint8).copy()


# ---------- Numba-compiled SHA256d(midstate) scanner ----------

def _define_numba_impl():
    # Define compiled functions only if numba is available
    global find_share_bounded_numba

    if not _HAS_NUMBA:
        def find_share_bounded_numba(*args, **kwargs):  # type: ignore
            return None
        return

    import numpy as _np  # type: ignore

    @njit(cache=True)
    def _rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @njit(cache=True)
    def _ch(x: int, y: int, z: int) -> int:
        return (x & y) ^ ((~x) & z)

    @njit(cache=True)
    def _maj(x: int, y: int, z: int) -> int:
        return (x & y) ^ (x & z) ^ (y & z)

    @njit(cache=True)
    def _bsig0(x: int) -> int:
        return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

    @njit(cache=True)
    def _bsig1(x: int) -> int:
        return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

    @njit(cache=True)
    def _ssig0(x: int) -> int:
        return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)

    @njit(cache=True)
    def _ssig1(x: int) -> int:
        return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)

    @njit(cache=True)
    def _load_u32_be(b0: int, b1: int, b2: int, b3: int) -> int:
        return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xFFFFFFFF

    @njit(cache=True)
    def _compress(state: _np.ndarray, block64: _np.ndarray) -> None:
        W = _np.zeros(64, dtype=_np.uint32)

        for i in range(16):
            j = 4 * i
            W[i] = _load_u32_be(int(block64[j]), int(block64[j + 1]), int(block64[j + 2]), int(block64[j + 3]))

        for i in range(16, 64):
            W[i] = (W[i - 16] + _ssig0(int(W[i - 15])) + W[i - 7] + _ssig1(int(W[i - 2]))) & 0xFFFFFFFF

        a = int(state[0]); b = int(state[1]); c = int(state[2]); d = int(state[3])
        e = int(state[4]); f = int(state[5]); g = int(state[6]); h = int(state[7])

        for i in range(64):
            t1 = (h + _bsig1(e) + _ch(e, f, g) + _SHA256_K[i] + int(W[i])) & 0xFFFFFFFF
            t2 = (_bsig0(a) + _maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        state[0] = (int(state[0]) + a) & 0xFFFFFFFF
        state[1] = (int(state[1]) + b) & 0xFFFFFFFF
        state[2] = (int(state[2]) + c) & 0xFFFFFFFF
        state[3] = (int(state[3]) + d) & 0xFFFFFFFF
        state[4] = (int(state[4]) + e) & 0xFFFFFFFF
        state[5] = (int(state[5]) + f) & 0xFFFFFFFF
        state[6] = (int(state[6]) + g) & 0xFFFFFFFF
        state[7] = (int(state[7]) + h) & 0xFFFFFFFF

    @njit(cache=True)
    def _sha256_midstate(block0: _np.ndarray) -> _np.ndarray:
        st = _np.array(_SHA256_H0, dtype=_np.uint32)
        _compress(st, block0)
        return st

    @njit(cache=True)
    def _sha256_finish_from_state(state_after_block0: _np.ndarray, block1: _np.ndarray, out32: _np.ndarray) -> None:
        st = state_after_block0.copy()
        _compress(st, block1)
        # digest big-endian bytes
        for i in range(8):
            w = int(st[i])
            out32[4 * i + 0] = (w >> 24) & 0xFF
            out32[4 * i + 1] = (w >> 16) & 0xFF
            out32[4 * i + 2] = (w >> 8) & 0xFF
            out32[4 * i + 3] = w & 0xFF

    @njit(cache=True)
    def _sha256_one_block(msg: _np.ndarray, msg_len: int, out32: _np.ndarray) -> None:
        # build padded 64-byte block
        block = _np.zeros(64, dtype=_np.uint8)
        for i in range(msg_len):
            block[i] = msg[i]
        block[msg_len] = 0x80

        bitlen = msg_len * 8
        # 64-bit big-endian length at end
        block[63] = bitlen & 0xFF
        block[62] = (bitlen >> 8) & 0xFF
        block[61] = (bitlen >> 16) & 0xFF
        block[60] = (bitlen >> 24) & 0xFF
        # upper 4 bytes are zero for msg_len <= 55

        st = _np.array(_SHA256_H0, dtype=_np.uint32)
        _compress(st, block)

        for i in range(8):
            w = int(st[i])
            out32[4 * i + 0] = (w >> 24) & 0xFF
            out32[4 * i + 1] = (w >> 16) & 0xFF
            out32[4 * i + 2] = (w >> 8) & 0xFF
            out32[4 * i + 3] = w & 0xFF

    @njit(cache=True)
    def _hash_leq_target_bitcoin(hash32_be: _np.ndarray, target32_be: _np.ndarray) -> bool:
        # Bitcoin compares uint256 little-endian values.
        # Equivalent: compare reversed digest bytes (big-endian) to target big-endian.
        for i in range(32):
            hb = int(hash32_be[31 - i])  # reverse
            tb = int(target32_be[i])
            if hb < tb:
                return True
            if hb > tb:
                return False
        return True

    @njit(cache=True)
    def _find_nonce_midstate(header76_u8: _np.ndarray, start_nonce: int, count: int, target32_be: _np.ndarray) -> int:
        # block0 = first 64 bytes of header
        block0 = _np.empty(64, dtype=_np.uint8)
        for i in range(64):
            block0[i] = header76_u8[i]
        mid = _sha256_midstate(block0)

        # Build constant part of block1 (second block for an 80-byte message)
        # block1[0:12] = header76[64:76]
        # block1[12:16] = nonce (little-endian)
        # block1[16] = 0x80
        # block1[56:64] = bitlen=640 big-endian => ... 0x02 0x80
        block1 = _np.zeros(64, dtype=_np.uint8)
        for i in range(12):
            block1[i] = header76_u8[64 + i]
        block1[16] = 0x80
        block1[62] = 0x02
        block1[63] = 0x80

        h1 = _np.empty(32, dtype=_np.uint8)
        h2 = _np.empty(32, dtype=_np.uint8)

        nonce = start_nonce & 0xFFFFFFFF
        for _ in range(count):
            block1[12] = nonce & 0xFF
            block1[13] = (nonce >> 8) & 0xFF
            block1[14] = (nonce >> 16) & 0xFF
            block1[15] = (nonce >> 24) & 0xFF

            _sha256_finish_from_state(mid, block1, h1)
            _sha256_one_block(h1, 32, h2)

            if _hash_leq_target_bitcoin(h2, target32_be):
                return nonce

            nonce = (nonce + 1) & 0xFFFFFFFF

        return -1

    def find_share_bounded_numba(
        header76: bytes,
        target_int: int,
        start_nonce: int,
        count: int,
    ) -> Optional[int]:
        if not isinstance(header76, (bytes, bytearray)) or len(header76) != 76:
            raise ValueError("header76 must be 76 bytes")
        if count <= 0:
            return None

        h = _np.frombuffer(bytes(header76), dtype=_np.uint8)
        tgt = _target_int_to_be_u8(int(target_int))
        n = _find_nonce_midstate(h, int(start_nonce) & 0xFFFFFFFF, int(count), tgt)
        return None if int(n) < 0 else int(n)

    # export
    globals()["find_share_bounded_numba"] = find_share_bounded_numba


_define_numba_impl()


def find_share_bounded_numba(
    header76: bytes,
    target_int: int,
    start_nonce: int,
    count: int,
) -> Optional[int]:
    # replaced by _define_numba_impl() when numba is available
    return None
