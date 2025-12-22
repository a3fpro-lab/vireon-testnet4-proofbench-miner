from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .protocol import SubscribeInfo, parse_subscribe_reply, is_method


class JsonLineReader:
    """
    Newline-delimited JSON reader that:
      - preserves leftover bytes across reads
      - does NOT drop extra lines from the same recv()
    """
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def read_one(self) -> Dict[str, Any]:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk

        line, self.buf = self.buf.split(b"\n", 1)
        line = line.strip()
        if not line:
            return self.read_one()
        return json.loads(line.decode())


def _send_json_line(sock: socket.socket, obj: Dict[str, Any]) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())


@dataclass(frozen=True)
class HandshakeResult:
    subscribe: SubscribeInfo
    authorized: bool
    # Any notifications received during handshake, useful for debugging / warm-start.
    early_messages: Tuple[Dict[str, Any], ...] = ()


def connect_and_handshake(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 5.0,
) -> HandshakeResult:
    """
    Robust Stratum v1 handshake:
      - send mining.subscribe, read messages until reply with id==1
      - send mining.authorize, read messages until reply with id==2
      - tolerate notifications interleaved anywhere
    """
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        r = JsonLineReader(sock)

        early: List[Dict[str, Any]] = []

        # 1) subscribe
        _send_json_line(sock, {"id": 1, "method": "mining.subscribe", "params": ["vireon/0.1"]})

        sub_reply: Optional[Dict[str, Any]] = None
        while sub_reply is None:
            msg = r.read_one()
            # Reply messages have "id"; notifications typically have id=None
            if msg.get("id") == 1:
                sub_reply = msg
            else:
                early.append(msg)

        sub_info = parse_subscribe_reply(sub_reply)

        # 2) authorize
        _send_json_line(sock, {"id": 2, "method": "mining.authorize", "params": [username, password]})

        auth_reply: Optional[Dict[str, Any]] = None
        while auth_reply is None:
            msg = r.read_one()
            if msg.get("id") == 2:
                auth_reply = msg
            else:
                early.append(msg)

        if auth_reply.get("error"):
            raise ValueError(f"authorize error: {auth_reply['error']}")

        authorized = bool(auth_reply.get("result") is True)
        return HandshakeResult(subscribe=sub_info, authorized=authorized, early_messages=tuple(early))


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
