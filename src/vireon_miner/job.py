from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence
import struct

from .hashing import sha256d


# Bitcoin difficulty-1 target (used for Stratum share difficulty math)
DIFF1_TARGET = int(
    "00000000FFFF0000000000000000000000000000000000000000000000000000", 16
)


def target_from_difficulty(diff: float) -> int:
    """
    Stratum share target from difficulty.
    target = DIFF1_TARGET / diff
    """
    if diff <= 0:
        raise ValueError("difficulty must be > 0")
    return int(DIFF1_TARGET / diff)


def _u32le_from_hex(hex_u32: str) -> bytes:
    return struct.pack("<I", int(hex_u32, 16))


def _le_bytes_from_hex_hash(hex_32bytes: str) -> bytes:
    """
    Stratum sends hashes as hex (human/big-endian). Internal header uses little-endian bytes.
    """
    b = bytes.fromhex(hex_32bytes)
    if len(b) != 32:
        raise ValueError("expected 32-byte hash hex")
    return b[::-1]


def merkle_root_le(
    coinb1_hex: str,
    coinb2_hex: str,
    extranonce1_hex: str,
    extranonce2_hex: str,
    merkle_branch_hex: Sequence[str],
) -> bytes:
    """
    Returns merkle root bytes in LITTLE-ENDIAN form ready for block header serialization.

    Convention (Stratum-standard):
    - merkle branch items are provided as big-endian hex; we reverse to little-endian for hashing.
    - intermediate hash values are tracked in little-endian.
    """
    coinbase = (
        bytes.fromhex(coinb1_hex)
        + bytes.fromhex(extranonce1_hex)
        + bytes.fromhex(extranonce2_hex)
        + bytes.fromhex(coinb2_hex)
    )

    h = sha256d(coinbase)[::-1]  # little-endian

    for br_hex in merkle_branch_hex:
        br_le = _le_bytes_from_hex_hash(br_hex)
        h = sha256d(h + br_le)[::-1]  # stay little-endian

    return h


def build_header_80(
    version_hex: str,
    prevhash_hex: str,
    merkle_root_le_bytes: bytes,
    ntime_hex: str,
    nbits_hex: str,
    nonce_hex: str,
) -> bytes:
    """
    Build 80-byte Bitcoin header:
    version(4 LE) || prevhash(32 LE) || merkleroot(32 LE) || ntime(4 LE) || nbits(4 LE) || nonce(4 LE)
    """
    if len(merkle_root_le_bytes) != 32:
        raise ValueError("merkle_root_le_bytes must be 32 bytes")
    return (
        _u32le_from_hex(version_hex)
        + _le_bytes_from_hex_hash(prevhash_hex)
        + merkle_root_le_bytes
        + _u32le_from_hex(ntime_hex)
        + _u32le_from_hex(nbits_hex)
        + _u32le_from_hex(nonce_hex)
    )


def header_hash_int_le(header80: bytes) -> int:
    """
    Double-SHA256(header) interpreted as Bitcoin's little-endian 256-bit integer.
    """
    h = sha256d(header80)
    return int.from_bytes(h[::-1], "big")


@dataclass(frozen=True)
class StratumJob:
    job_id: str
    prevhash_hex: str
    coinb1_hex: str
    coinb2_hex: str
    merkle_branch_hex: list[str]
    version_hex: str
    nbits_hex: str
    ntime_hex: str
    clean_jobs: bool

    @staticmethod
    def from_notify_params(params: list) -> "StratumJob":
        # mining.notify params:
        # [job_id, prevhash, coinb1, coinb2, merkle_branch[], version, nbits, ntime, clean_jobs]
        return StratumJob(
            job_id=params[0],
            prevhash_hex=params[1],
            coinb1_hex=params[2],
            coinb2_hex=params[3],
            merkle_branch_hex=list(params[4]),
            version_hex=params[5],
            nbits_hex=params[6],
            ntime_hex=params[7],
            clean_jobs=bool(params[8]),
        )
