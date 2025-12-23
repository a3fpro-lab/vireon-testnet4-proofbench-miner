from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Literal

from .scan import find_share_bounded as find_share_bounded_py

try:
    from .fastscan_numba import available as numba_available, find_share_bounded_numba
except Exception:
    def numba_available() -> bool:  # type: ignore
        return False
    def find_share_bounded_numba(*args, **kwargs):  # type: ignore
        return None


Backend = Literal["python", "numba-midstate"]


@dataclass(frozen=True)
class ScanResult:
    nonce: int
    backend: Backend


def find_share_bounded_auto(
    header76: bytes,
    target_int: int,
    start_nonce: int,
    count: int,
    prefer: Backend = "numba-midstate",
) -> Optional[ScanResult]:
    """
    Unified API:
      - tries Numba (if available) when prefer="numba-midstate"
      - otherwise falls back to pure python scan.py
    """
    if prefer == "numba-midstate" and numba_available():
        n = find_share_bounded_numba(header76, target_int, start_nonce=start_nonce, count=count)
        if n is not None:
            return ScanResult(nonce=int(n), backend="numba-midstate")

    r = find_share_bounded_py(header76, target_int, start_nonce=start_nonce, count=count)
    if r is None:
        return None
    return ScanResult(nonce=int(r.nonce), backend="python")
