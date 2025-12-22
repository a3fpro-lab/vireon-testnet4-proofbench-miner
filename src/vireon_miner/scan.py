from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class ShareResult:
    nonce: int
    hash_hex: str
    hash_int: int


def _sha256d(b: bytes) -> bytes:
    """Bitcoin double-SHA256."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _meets_target(hash32: bytes, target_int: int) -> bool:
    return int.from_bytes(hash32[::-1], "big") <= target_int


def find_share_bounded(header76: bytes, target_int: int, start_nonce: int, count: int) -> Optional[ShareResult]:
    """
    Brute-force scan nonces in [start_nonce, start_nonce+count) for a hash <= target_int.

    - header76: 76-byte block header prefix (everything except the 4-byte nonce).
    - target_int: integer target threshold.
    - start_nonce: starting nonce (0..2^32-1).
    - count: how many sequential nonces to try.

    Returns first ShareResult found, else None.
    """
    if not isinstance(header76, (bytes, bytearray)) or len(header76) != 76:
        raise ValueError("header76 must be 76 bytes")
    if count <= 0:
        return None

    # Ensure 32-bit wrap semantics.
    n = start_nonce & 0xFFFFFFFF

    for _ in range(count):
        nonce_bytes = (n & 0xFFFFFFFF).to_bytes(4, "little")
        h = _sha256d(header76 + nonce_bytes)
        if _meets_target(h, target_int):
            hi = int.from_bytes(h, "big")
            return ShareResult(nonce=n, hash_hex=h[::-1].hex(), hash_int=hi)
        n = (n + 1) & 0xFFFFFFFF

    return None
