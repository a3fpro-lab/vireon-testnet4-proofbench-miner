from __future__ import annotations

import json
import socket
import threading
import time
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .scan import find_share_bounded


# Difficulty-1 target (Bitcoin convention)
DIFF1_TARGET_INT = int(
    "00000000ffff0000000000000000000000000000000000000000000000000000", 16
)


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def diff_to_target_int(diff: float) -> int:
    if diff <= 0:
        raise ValueError("diff must be > 0")
    # share_target = DIFF1_TARGET / diff
    return int(DIFF1_TARGET_INT / float(diff))


def meets_target(hash32: bytes, target_int: int) -> bool:
    return int.from_bytes(hash32, "big") <= target_int


def extranonce2_from_counter(counter: int, size: int) -> str:
    if size <= 0:
        raise ValueError("size must be > 0")
    return int(counter).to_bytes(size, "big", signed=False).hex()


def merkle_root_from_coinbase(
    coinb1_hex: str,
    coinb2_hex: str,
    extranonce1_hex: str,
    extranonce2_hex: str,
    merkle_branch_hex: List[str],
) -> bytes:
    # coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    coinbase_hex = coinb1_hex + extranonce1_hex + extranonce2_hex + coinb2_hex
    h = sha256d(bytes.fromhex(coinbase_hex))
    for bhex in merkle_branch_hex:
        h = sha256d(h + bytes.fromhex(bhex))
    return h  # 32 bytes


def build_header76(
    version_hex: str,
    prevhash_hex: str,
    merkle_root: bytes,
    ntime_hex: str,
    nbits_hex: str,
) -> bytes:
    if len(version_hex) != 8 or len(ntime_hex) != 8 or len(nbits_hex) != 8:
        raise ValueError("version/ntime/nbits must be 8 hex chars each")
    if len(prevhash_hex) != 64:
        raise ValueError("prevhash must be 64 hex chars")
    if len(merkle_root) != 32:
        raise ValueError("merkle_root must be 32 bytes")

    version_le = bytes.fromhex(version_hex)[::-1]
    prev_le = bytes.fromhex(prevhash_hex)[::-1]
    merkle_le = merkle_root[::-1]
    ntime_le = bytes.fromhex(ntime_hex)[::-1]
    nbits_le = bytes.fromhex(nbits_hex)[::-1]

    header76 = version_le + prev_le + merkle_le + ntime_le + nbits_le
    if len(header76) != 76:
        raise AssertionError("header76 must be 76 bytes")
    return header76


class JsonLineReader:
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


def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())


@dataclass
class Job:
    job_id: str
    prevhash: str
    coinb1: str
    coinb2: str
    merkle_branch: List[str]
    version: str
    nbits: str
    ntime: str
    clean_jobs: bool
    received_at: float


@dataclass
class LiveConfig:
    host: str
    port: int
    username: str
    password: str = "x"
    timeout: float = 10.0

    # Mining loop
    batch_nonces: int = 200_000
    stale_seconds: float = 120.0
    suggest_difficulty: Optional[float] = 1.0

    # Logging
    log_every_seconds: float = 5.0


class LiveStratumClient:
    def __init__(self, cfg: LiveConfig):
        self.cfg = cfg
        self.sock: Optional[socket.socket] = None
        self.reader: Optional[JsonLineReader] = None

        self.extranonce1: Optional[str] = None
        self.extranonce2_size: Optional[int] = None

        self.current_diff: float = 1.0
        self.current_target_int: int = diff_to_target_int(1.0)

        self.job_lock = threading.Lock()
        self.job: Optional[Job] = None

        self.stop_evt = threading.Event()

        # Stats
        self.accepted = 0
        self.rejected = 0
        self.submitted = 0
        self.hashes = 0
        self.t0 = time.time()

        self._en2_counter = 0

    def connect(self) -> None:
        s = socket.create_connection((self.cfg.host, self.cfg.port), timeout=self.cfg.timeout)
        s.settimeout(self.cfg.timeout)
        self.sock = s
        self.reader = JsonLineReader(s)

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None
            self.reader = None

    def subscribe_and_authorize(self) -> None:
        assert self.sock and self.reader

        send_json(self.sock, {"id": 1, "method": "mining.subscribe", "params": ["vireon-live/0.1"]})
        sub = self._wait_for_id(1)
        if sub.get("error"):
            raise RuntimeError(f"subscribe error: {sub['error']}")
        result = sub.get("result")
        if not (isinstance(result, list) and len(result) >= 3):
            raise RuntimeError(f"bad subscribe result: {result!r}")

        self.extranonce1 = result[1]
        self.extranonce2_size = int(result[2])

        send_json(self.sock, {"id": 2, "method": "mining.authorize", "params": [self.cfg.username, self.cfg.password]})
        auth = self._wait_for_id(2)
        if auth.get("error"):
            raise RuntimeError(f"authorize error: {auth['error']}")
        if auth.get("result") is not True:
            raise RuntimeError("authorize failed (result != true)")

        if self.cfg.suggest_difficulty is not None:
            send_json(self.sock, {"id": 3, "method": "mining.suggest_difficulty", "params": [float(self.cfg.suggest_difficulty)]})
            # pools may reply or ignore; we don't block on it

    def _wait_for_id(self, want_id: int) -> Dict[str, Any]:
        assert self.reader
        while True:
            msg = self.reader.read_one()
            # Interleaved notifications can show up here; process them.
            if msg.get("id") == want_id:
                return msg
            self._handle_message(msg)

    def _handle_message(self, msg: Dict[str, Any]) -> None:
        method = msg.get("method")
        if method == "mining.set_difficulty":
            params = msg.get("params")
            if isinstance(params, list) and params:
                try:
                    self.current_diff = float(params[0])
                    self.current_target_int = diff_to_target_int(self.current_diff)
                except Exception:
                    pass

        elif method == "mining.notify":
            p = msg.get("params")
            if isinstance(p, list) and len(p) >= 9:
                job = Job(
                    job_id=str(p[0]),
                    prevhash=str(p[1]),
                    coinb1=str(p[2]),
                    coinb2=str(p[3]),
                    merkle_branch=list(p[4]) if isinstance(p[4], list) else [],
                    version=str(p[5]),
                    nbits=str(p[6]),
                    ntime=str(p[7]),
                    clean_jobs=bool(p[8]),
                    received_at=time.time(),
                )
                with self.job_lock:
                    self.job = job

        elif msg.get("id") is not None:
            # submit replies come here (id == submit id)
            # handled by submit() waiting on that id
            pass

    def run_network_loop(self) -> None:
        """Continuously read messages and update job/difficulty."""
        assert self.reader
        while not self.stop_evt.is_set():
            try:
                msg = self.reader.read_one()
                self._handle_message(msg)
            except (socket.timeout, TimeoutError):
                continue
            except Exception:
                # break on hard errors; caller should reconnect
                break

    def _next_extranonce2(self) -> str:
        assert self.extranonce2_size is not None
        self._en2_counter += 1
        return extranonce2_from_counter(self._en2_counter, self.extranonce2_size)

    def submit_share(self, job: Job, extranonce2_hex: str, nonce: int) -> bool:
        """
        mining.submit params: [worker_name, job_id, extranonce2, ntime, nonce]
        nonce is 4 bytes, little-endian hex.
        """
        assert self.sock and self.reader
        submit_id = int(time.time() * 1000) & 0x7FFFFFFF

        nonce_hex = (nonce & 0xFFFFFFFF).to_bytes(4, "little").hex()
        send_json(self.sock, {
            "id": submit_id,
            "method": "mining.submit",
            "params": [self.cfg.username, job.job_id, extranonce2_hex, job.ntime, nonce_hex],
        })
        self.submitted += 1

        # Wait for that response id; process other notifications while waiting
        while True:
            msg = self.reader.read_one()
            if msg.get("id") == submit_id:
                if msg.get("error"):
                    self.rejected += 1
                    return False
                ok = (msg.get("result") is True)
                if ok:
                    self.accepted += 1
                else:
                    self.rejected += 1
                return ok
            else:
                self._handle_message(msg)

    def run_mining_loop(self) -> None:
        """
        Main mining loop:
          - waits for a job
          - chooses an extranonce2
          - builds header76
          - scans nonces in batches
          - submits first found share
        """
        if self.extranonce1 is None or self.extranonce2_size is None:
            raise RuntimeError("must subscribe before mining")

        last_log = time.time()

        while not self.stop_evt.is_set():
            with self.job_lock:
                job = self.job

            if job is None:
                time.sleep(0.1)
                continue

            # stale guard
            if (time.time() - job.received_at) > self.cfg.stale_seconds:
                time.sleep(0.05)
                continue

            extranonce2 = self._next_extranonce2()
            merkle = merkle_root_from_coinbase(
                coinb1_hex=job.coinb1,
                coinb2_hex=job.coinb2,
                extranonce1_hex=self.extranonce1,
                extranonce2_hex=extranonce2,
                merkle_branch_hex=job.merkle_branch,
            )
            header76 = build_header76(
                version_hex=job.version,
                prevhash_hex=job.prevhash,
                merkle_root=merkle,
                ntime_hex=job.ntime,
                nbits_hex=job.nbits,
            )

            # scan batches sequentially; later we thread this
            start_nonce = 0
            res = find_share_bounded(
                header76=header76,
                target_int=self.current_target_int,
                start_nonce=start_nonce,
                count=int(self.cfg.batch_nonces),
            )
            self.hashes += int(self.cfg.batch_nonces)

            if res is not None:
                ok = self.submit_share(job, extranonce2, res.nonce)
                # If share accepted/rejected, continue on same job; pool may send clean_jobs.
                _ = ok

            now = time.time()
            if (now - last_log) >= self.cfg.log_every_seconds:
                dt = max(1e-9, now - self.t0)
                mhps = (self.hashes / dt) / 1e6
                print(f"[STATS] mh/s={mhps:.3f} submitted={self.submitted} acc={self.accepted} rej={self.rejected} diff={self.current_diff}")
                last_log = now


def run_live(cfg: LiveConfig) -> None:
    backoff = 1.0
    while True:
        c = LiveStratumClient(cfg)
        try:
            c.connect()
            print(f"[NET] connected {cfg.host}:{cfg.port}")
            c.subscribe_and_authorize()
            print(f"[POOL] authorized. extranonce1={c.extranonce1} en2_size={c.extranonce2_size}")

            net_th = threading.Thread(target=c.run_network_loop, daemon=True)
            net_th.start()

            c.run_mining_loop()

        except KeyboardInterrupt:
            c.stop_evt.set()
            c.close()
            return
        except Exception as e:
            print(f"[ERR] {type(e).__name__}: {e}")
            c.stop_evt.set()
            c.close()
            time.sleep(backoff)
            backoff = min(30.0, backoff * 2.0)
            continue
