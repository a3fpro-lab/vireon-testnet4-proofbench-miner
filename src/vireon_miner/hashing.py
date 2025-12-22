from __future__ import annotations

import hashlib


def sha256d(data: bytes) -> bytes:
    """
    Bitcoin-style double-SHA256.
    Returns raw 32-byte digest.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
