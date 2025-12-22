from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .protocol import SubscribeInfo, parse_subscribe_reply, is_method


def _send_json_line(sock: socket.socket, obj: Dict[str, Any]) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())


def _recv_json_line(sock: socket.socket) -> Dict[str, Any]:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line.decode())


@dataclass(frozen=True)
class HandshakeResult:
    subscribe: SubscribeInfo
    authorized: bool


def connect_and_handshake(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 5.0,
) -> HandshakeResult:
    """
    Minimal Stratum v1 handshake:
      mining.subscribe -> parse extranonce
      mining.authorize -> bool
    """
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)

        _send_json_line(sock, {"id": 1, "method": "mining.subscribe", "params": ["vireon/0.1"]})
        sub_reply = _recv_json_line(sock)
        sub_info = parse_subscribe_reply(sub_reply)

        _send_json_line(sock, {"id": 2, "method": "mining.authorize", "params": [username, password]})
        auth_reply = _recv_json_line(sock)

        if auth_reply.get("error"):
            raise ValueError(f"authorize error: {auth_reply['error']}")
        authorized = bool(auth_reply.get("result") is True)

        return HandshakeResult(subscribe=sub_info, authorized=authorized)


def parse_set_difficulty(msg: Dict[str, Any]) -> Optional[float]:
    if not is_method(msg, "mining.set_difficulty"):
        return None
    params = msg.get("params")
    if not isinstance(params, list) or not params:
        return None
    try:
        return float(params[0])
    except Exception:
        return None


def parse_notify(msg: Dict[str, Any]) -> Optional[Tuple[str, str, str, str, str, str, str, bool]]:
    if not is_method(msg, "mining.notify"):
        return None
    p = msg.get("params")
    if not isinstance(p, list) or len(p) < 9:
        return None

    job_id = p[0]
    prevhash = p[1]
    coinb1 = p[2]
    coinb2 = p[3]
    version = p[5]
    nbits = p[6]
    ntime = p[7]
    clean = bool(p[8])

    if not all(isinstance(x, str) for x in [job_id, prevhash, coinb1, coinb2, version, nbits, ntime]):
        return None

    return (job_id, prevhash, coinb1, coinb2, version, nbits, ntime, clean)
