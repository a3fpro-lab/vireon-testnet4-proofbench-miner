from __future__ import annotations

import argparse
import sys

from .config import PRESET_TESTNET4_BRAIINS
from .hashing import sha256d
from .miner import connect_and_handshake, run_live
from .stratum import StratumMsg


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vireon-miner")

    p.add_argument("--echo", action="store_true", help="Print sample Stratum message and exit.")
    p.add_argument("--selftest", action="store_true", help="Run a tiny local hash self-test and exit.")
    p.add_argument("--handshake", action="store_true", help="Connect + do subscribe/authorize, then exit.")

    p.add_argument("--live", action="store_true", help="Run live loop: wait for diff+notify, scan, submit.")
    p.add_argument("--max-shares", type=int, default=1, help="Stop after this many accepted shares (default 1).")
    p.add_argument("--nonce-start", type=int, default=0, help="Start nonce for each bounded scan.")
    p.add_argument("--nonce-count", type=int, default=100_000, help="How many nonces to scan per job.")

    p.add_argument("--testnet4-braiins", action="store_true", help="Preset host/port for Braiins testnet4.")
    p.add_argument("--host", default="127.0.0.1", help="Stratum host (plaintext TCP).")
    p.add_argument("--port", type=int, default=3333, help="Stratum port (plaintext TCP).")
    p.add_argument("--user", default="t1.vireon.worker", help="Stratum username.")
    p.add_argument("--password", default="x", help="Stratum password.")
    p.add_argument("--timeout", type=float, default=10.0, help="Socket timeout seconds.")

    args = p.parse_args(argv)

    if args.echo:
        msg = StratumMsg("mining.subscribe", ["vireon/0.1"], msg_id=1)
        sys.stdout.buffer.write(msg.to_json_line())
        return 0

    if args.selftest:
        print(sha256d(b"\x00" * 80).hex())
        return 0

    host, port = (args.host, args.port)
    if args.testnet4_braiins:
        host, port = PRESET_TESTNET4_BRAIINS

    if args.handshake:
        res = connect_and_handshake(
            host=host,
            port=port,
            username=args.user,
            password=args.password,
            timeout_s=args.timeout,
            agent="vireon/0.1",
        )
        print({"subscribe_id": res.subscribe_reply.get("id"), "authorize_result": res.authorize_reply.get("result")})
        return 0

    if args.live:
        return run_live(
            host=host,
            port=port,
            username=args.user,
            password=args.password,
            timeout_s=args.timeout,
            agent="vireon/0.1",
            nonce_start=args.nonce_start,
            nonce_count=args.nonce_count,
            max_shares=args.max_shares,
        )

    print("Nothing to do. Try --handshake or --live.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
