from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MinerConfig:
    host: str
    port: int
    username: str
    password: str
    timeout_s: float = 10.0


# Presets (no TLS here yet; this is raw TCP Stratum)
PRESET_TESTNET4_BRAIINS = ("stratum.braiins.com", 3334)
