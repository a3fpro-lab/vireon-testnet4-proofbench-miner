from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any

from .stratum import StratumMsg, parse_json_line


class StratumProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class HandshakeResult:
    subscribe_reply: dict[str, Any]
    authorize_reply: dict[str, Any]


def connect_and_handshake(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    timeout_s: float = 10.0,
    agent: str = "vireon/0.1",
) -> HandshakeResult:
    """
    Minimal Stratum v1 handshake (plaintext TCP):
    1) mining.subscribe
    2) mining.authorize

    This is intentionally small + testable. Mining loop comes next.
    """
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        f = s.makefile("rwb")

        # 1) subscribe
        f.write(StratumMsg("mining.subscribe", [agent], msg_id=1).to_json_line())
        f.flush()
        line = f.readline()
        if not line:
            raise StratumProtocolError("EOF during subscribe reply")
        sub = parse_json_line(line)

        # 2) authorize
        f.write(StratumMsg("mining.authorize", [username, password], msg_id=2).to_json_line())
        f.flush()
        line = f.readline()
        if not line:
            raise StratumProtocolError("EOF during authorize reply")
        auth = parse_json_line(line)

        return HandshakeResult(subscribe_reply=sub, authorize_reply=auth)
