from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any

from .protocol import parse_subscribe_reply, is_method, SubscribeInfo
from .job import StratumJob
from .scan import find_share_bounded
from .stratum import StratumMsg, parse_json_line


class StratumProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class HandshakeResult:
    subscribe_reply: dict[str, Any]
    authorize_reply: dict[str, Any]


def _read_json_line(f) -> dict[str, Any]:
    line = f.readline()
    if not line:
        raise StratumProtocolError("EOF from stratum server")
    return parse_json_line(line)


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
    - send mining.subscribe (id=1)
    - send mining.authorize (id=2)
    - read until we receive matching id replies (server may interleave notifications)
    """
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        f = s.makefile("rwb")

        f.write(StratumMsg("mining.subscribe", [agent], msg_id=1).to_json_line())
        f.write(StratumMsg("mining.authorize", [username, password], msg_id=2).to_json_line())
        f.flush()

        sub = None
        auth = None

        while sub is None or auth is None:
            msg = _read_json_line(f)
            mid = msg.get("id", None)
            if mid == 1:
                sub = msg
            elif mid == 2:
                auth = msg
            else:
                # ignore async notifications during handshake
                continue

        return HandshakeResult(subscribe_reply=sub, authorize_reply=auth)


def run_live(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    timeout_s: float = 10.0,
    agent: str = "vireon/0.1",
    nonce_start: int = 0,
    nonce_count: int = 100_000,
    max_shares: int = 1,
) -> int:
    """
    Live miner loop (SAFE defaults):
    - max_shares defaults to 1
    - bounded nonce scan per job
    - plaintext Stratum only (TLS later)

    Returns exit code.
    """
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        f = s.makefile("rwb")

        # subscribe + authorize
        f.write(StratumMsg("mining.subscribe", [agent], msg_id=1).to_json_line())
        f.write(StratumMsg("mining.authorize", [username, password], msg_id=2).to_json_line())
        f.flush()

        # read until we have subscribe+authorize replies
        sub_reply = None
        auth_reply = None
        while sub_reply is None or auth_reply is None:
            msg = _read_json_line(f)
            if msg.get("id") == 1:
                sub_reply = msg
            elif msg.get("id") == 2:
                auth_reply = msg

        if auth_reply.get("result") is not True:
            raise StratumProtocolError(f"authorize failed: {auth_reply}")

        sub_info: SubscribeInfo = parse_subscribe_reply(sub_reply)

        difficulty = 1.0
        shares_found = 0
        submit_id = 4
        extranonce2_counter = 0

        while shares_found < max_shares:
            msg = _read_json_line(f)

            # Difficulty updates
            if is_method(msg, "mining.set_difficulty"):
                params = msg["params"]
                if not params:
                    continue
                difficulty = float(params[0])
                continue

            # New job
            if is_method(msg, "mining.notify"):
                job = StratumJob.from_notify_params(msg["params"])

                share, submit = find_share_bounded(
                    job,
                    username=username,
                    extranonce1_hex=sub_info.extranonce1_hex,
                    extranonce2_size=sub_info.extranonce2_size,
                    difficulty=difficulty,
                    extranonce2_counter=extranonce2_counter,
                    nonce_start=nonce_start,
                    nonce_count=nonce_count,
                )
                extranonce2_counter += 1

                if share is None or submit is None:
                    continue

                # send submit
                submit = StratumMsg(submit.method, submit.params, msg_id=submit_id)
                f.write(submit.to_json_line())
                f.flush()

                # wait for submit reply
                while True:
                    r = _read_json_line(f)
                    if r.get("id") == submit_id:
                        if r.get("result") is True:
                            shares_found += 1
                        else:
                            raise StratumProtocolError(f"submit rejected: {r}")
                        break

                submit_id += 1
                continue

        return 0
