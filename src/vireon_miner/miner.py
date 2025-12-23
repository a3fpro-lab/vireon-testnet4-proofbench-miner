from __future__ import annotations

import hashlib
import json
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .protocol import SubscribeInfo, parse_subscribe_reply, is_method
from .scan_auto import find_share_bounded_auto


# Difficulty-1 target (Bitcoin)
_DIFF1_TARGET = int(
    "00000000FFFF0000000000000000000000000000000000000000000000000000", 16
)


def _write_metrics(out_path: str, payload: dict) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


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
    timeout_s: float = 5.0,
    agent: str = "vireon/0.1",
    timeout: float | None = None,  # backward-compat alias
) -> HandshakeResult:
    """
    Robust Stratum v1 handshake:
      - send mining.subscribe, read messages until reply with id==1
      - send mining.authorize, read messages until reply with id==2
      - tolerate notifications interleaved anywhere
    """
    if timeout is not None:
        timeout_s = float(timeout)

    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        sock.settimeout(timeout_s)
        r = JsonLineReader(sock)

        early: List[Dict[str, Any]] = []

        # 1) subscribe
        _send_json_line(sock, {"id": 1, "method": "mining.subscribe", "params": [agent]})

        sub_reply: Optional[Dict[str, Any]] = None
        while sub_reply is None:
            msg = r.read_one()
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


def parse_notify_full(
    msg: Dict[str, Any],
) -> Optional[Tuple[str, str, str, str, List[str], str, str, str, bool]]:
    """
    mining.notify params:
      [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean]
    """
    if not is_method(msg, "mining.notify"):
        return None
    p = msg.get("params")
    if not isinstance(p, list) or len(p) < 9:
        return None

    job_id = p[0]
    prevhash = p[1]
    coinb1 = p[2]
    coinb2 = p[3]
    merkle_branch = p[4]
    version = p[5]
    nbits = p[6]
    ntime = p[7]
    clean = bool(p[8])

    if not all(isinstance(x, str) for x in [job_id, prevhash, coinb1, coinb2, version, nbits, ntime]):
        return None
    if not isinstance(merkle_branch, list) or not all(isinstance(x, str) for x in merkle_branch):
        return None

    return (job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean)


def _sha256d(b: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _merkle_root_from_coinbase(coinbase: bytes, branches_hex: List[str]) -> bytes:
    h = _sha256d(coinbase)
    for bh in branches_hex:
        h = _sha256d(h + bytes.fromhex(bh))
    return h  # 32 bytes


def _target_from_difficulty(diff: float) -> int:
    # Avoid div-by-zero and silly values
    if not (diff and diff > 0):
        return _DIFF1_TARGET
    # Use integer target
    t = int(_DIFF1_TARGET / diff)
    if t <= 0:
        t = 1
    return t


def run_live(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout_s: float,
    agent: str,
    nonce_start: int,
    nonce_count: int,
    max_shares: int,
    mode: str = "baseline",
    duration_sec: float = 600.0,
    out_path: str = "results/live_metrics.json",
    stale_seconds: float = 120.0,
) -> int:
    """
    Live Stratum loop:
      - handshake
      - track difficulty + latest job
      - scan bounded nonces for share
      - submit share
      - write metrics JSON on exit no matter what
    """
    t0 = time.time()
    hashes = 0
    submitted = 0
    accepted = 0
    rejected = 0
    jobs_seen = 0
    stale_jobs = 0
    last_backend = "python"
    last_diff: Optional[float] = None
    stop_reason = "unknown"

    # Job state
    cur_job: Optional[Tuple[str, str, str, str, List[str], str, str, str, bool]] = None
    job_rx_time: float = 0.0

    submit_id = 10  # start ids above handshake ids

    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            r = JsonLineReader(sock)

            # subscribe
            _send_json_line(sock, {"id": 1, "method": "mining.subscribe", "params": [agent]})
            sub_reply = None
            early: List[Dict[str, Any]] = []
            while sub_reply is None:
                msg = r.read_one()
                if msg.get("id") == 1:
                    sub_reply = msg
                else:
                    early.append(msg)

            sub_info = parse_subscribe_reply(sub_reply)
            extranonce1 = sub_info.extranonce1
            extranonce2_size = int(sub_info.extranonce2_size)

            # authorize
            _send_json_line(sock, {"id": 2, "method": "mining.authorize", "params": [username, password]})
            auth_reply = None
            while auth_reply is None:
                msg = r.read_one()
                if msg.get("id") == 2:
                    auth_reply = msg
                else:
                    early.append(msg)
            if auth_reply.get("error"):
                raise ValueError(f"authorize error: {auth_reply['error']}")
            if auth_reply.get("result") is not True:
                raise ValueError("authorize rejected")

            # process any early notifications
            for msg in early:
                d = parse_set_difficulty(msg)
                if d is not None:
                    last_diff = d
                n = parse_notify_full(msg)
                if n is not None:
                    cur_job = n
                    job_rx_time = time.time()

            # main loop
            while True:
                # stop after duration
                if time.time() - t0 >= duration_sec:
                    stop_reason = "duration"
                    break

                # Ensure we have fresh messages
                msg = r.read_one()

                d = parse_set_difficulty(msg)
                if d is not None:
                    last_diff = d
                    continue

                n = parse_notify_full(msg)
                if n is not None:
                    cur_job = n
                    job_rx_time = time.time()
                    jobs_seen += 1
                    continue

                # ignore other messages

                # Only scan when we have a job + difficulty
                if cur_job is None or last_diff is None:
                    continue

                # stale protection
                if time.time() - job_rx_time > stale_seconds:
                    stale_jobs += 1
                    continue

                job_id, prevhash, coinb1, coinb2, merkle_branch, version_hex, nbits_hex, ntime_hex, _clean = cur_job

                # mode switch: deterministic nonce jump per job
                local_nonce_start = int(nonce_start)
                if mode == "vireon":
                    h = hashlib.sha256(job_id.encode("utf-8")).digest()
                    local_nonce_start = int.from_bytes(h[:4], "little", signed=False)

                # Build coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
                extranonce2 = b"\x00" * extranonce2_size
                extranonce2_hex = extranonce2.hex()

                coinbase = bytes.fromhex(coinb1) + bytes.fromhex(extranonce1) + extranonce2 + bytes.fromhex(coinb2)
                merkle_root = _merkle_root_from_coinbase(coinbase, merkle_branch)

                # Build header76 (no nonce)
                ver_le = struct.pack("<I", int(version_hex, 16))
                prev_le = bytes.fromhex(prevhash)[::-1]
                mrkl_le = merkle_root[::-1]
                ntime_le = struct.pack("<I", int(ntime_hex, 16))
                nbits_le = struct.pack("<I", int(nbits_hex, 16))
                header76 = ver_le + prev_le + mrkl_le + ntime_le + nbits_le
                if len(header76) != 76:
                    continue

                # Share target from difficulty
                target_int = _target_from_difficulty(float(last_diff))

                # Scan bounded
                scan = find_share_bounded_auto(
                    header76=header76,
                    target_int=target_int,
                    start_nonce=local_nonce_start,
                    count=int(nonce_count),
                )
                hashes += int(nonce_count)

                if scan is None:
                    # advance baseline window next time
                    nonce_start = (local_nonce_start + int(nonce_count)) & 0xFFFFFFFF
                    continue

                last_backend = scan.backend

                # Submit share (nonce little-endian hex)
                nonce_le_hex = struct.pack("<I", int(scan.nonce) & 0xFFFFFFFF).hex()

                submitted += 1
                submit_id += 1
                _send_json_line(
                    sock,
                    {
                        "id": submit_id,
                        "method": "mining.submit",
                        "params": [username, job_id, extranonce2_hex, ntime_hex, nonce_le_hex],
                    },
                )

                # Wait for submit reply with matching id (ignore interleaved notify/diff)
                reply = None
                while reply is None:
                    m2 = r.read_one()
                    if m2.get("id") == submit_id:
                        reply = m2
                    else:
                        d2 = parse_set_difficulty(m2)
                        if d2 is not None:
                            last_diff = d2
                        n2 = parse_notify_full(m2)
                        if n2 is not None:
                            cur_job = n2
                            job_rx_time = time.time()
                            jobs_seen += 1

                if reply.get("error"):
                    rejected += 1
                else:
                    ok = bool(reply.get("result") is True)
                    if ok:
                        accepted += 1
                    else:
                        rejected += 1

                if accepted >= int(max_shares):
                    stop_reason = "max_shares"
                    break

    except Exception as e:
        stop_reason = f"exception:{type(e).__name__}"
        raise
    finally:
        dt = max(1e-9, time.time() - t0)
        metrics = {
            "mode": mode,
            "runtime_sec": dt,
            "hashes": int(hashes),
            "submitted": int(submitted),
            "accepted": int(accepted),
            "rejected": int(rejected),
            "accept_rate": (accepted / submitted) if submitted else 0.0,
            "reject_rate": (rejected / submitted) if submitted else 0.0,
            "share_yield": (accepted / hashes) if hashes else 0.0,
            "mhps": (hashes / dt) / 1e6,
            "backend": last_backend,
            "difficulty": last_diff,
            "jobs_seen": int(jobs_seen),
            "stale_jobs": int(stale_jobs),
            "stop_reason": stop_reason,
            "pool": {"host": host, "port": int(port)},
            "username": username,
        }
        _write_metrics(out_path, metrics)
        print(f"[METRICS] wrote {out_path}")

    return 0
