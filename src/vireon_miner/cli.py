from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, Tuple

from .config import PRESET_TESTNET4_BRAIINS
from .hashing import sha256d
from .miner import connect_and_handshake, run_live
from .stratum import StratumMsg


def _load_toml(path: str) -> Dict[str, Any]:
    try:
        import toml  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "Config requires 'toml'. Install it with: pip install toml"
        ) from e
    return toml.load(path)


def _cfg_get(cfg: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = cfg
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _preparse_config(argv: list[str] | None) -> Tuple[Dict[str, Any], list[str]]:
    p0 = argparse.ArgumentParser(add_help=False)
    p0.add_argument("--config", default=None, help="Path to TOML config (optional).")
    ns, rest = p0.parse_known_args(argv)
    if ns.config:
        return _load_toml(ns.config), rest
    return {}, rest


def main(argv: list[str] | None = None) -> int:
    cfg, rest = _preparse_config(argv)

    # Defaults come from config; CLI flags override after parse.
    default_host = _cfg_get(cfg, "pool", "host", default="127.0.0.1")
    default_port = int(_cfg_get(cfg, "pool", "port", default=3333))
    default_user = _cfg_get(cfg, "account", "user", default="t1.vireon.worker")
    default_password = _cfg_get(cfg, "account", "password", default="x")
    default_timeout = float(_cfg_get(cfg, "runtime", "timeout", default=10.0))
    default_nonce_start = int(_cfg_get(cfg, "runtime", "nonce_start", default=0))
    default_nonce_count = int(_cfg_get(cfg, "runtime", "nonce_count", default=100_000))
    default_max_shares = int(_cfg_get(cfg, "runtime", "max_shares", default=1))

    p = argparse.ArgumentParser(prog="vireon-miner")
    p.add_argument("--config", default=None, help="Path to TOML config (optional).")

    p.add_argument("--echo", action="store_true", help="Print sample Stratum message and exit.")
    p.add_argument("--selftest", action="store_true", help="Run a tiny local hash self-test and exit.")
    p.add_argument("--handshake", action="store_true", help="Connect + do subscribe/authorize, then exit.")

    p.add_argument("--live", action="store_true", help="Run live loop: wait for diff+notify, scan, submit.")
    p.add_argument("--max-shares", type=int, default=default_max_shares, help="Stop after this many accepted shares.")
    p.add_argument("--nonce-start", type=int, default=default_nonce_start, help="Start nonce for each bounded scan.")
    p.add_argument("--nonce-count", type=int, default=default_nonce_count, help="How many nonces to scan per job.")

    p.add_argument("--testnet4-braiins", action="store_true", help="Preset host/port for Braiins testnet4.")
    p.add_argument("--host", default=default_host, help="Stratum host (plaintext TCP).")
    p.add_argument("--port", type=int, default=default_port, help="Stratum port (plaintext TCP).")
    p.add_argument("--user", default=default_user, help="Stratum username.")
    p.add_argument("--password", default=default_password, help="Stratum password.")
    p.add_argument("--timeout", type=float, default=default_timeout, help="Socket timeout seconds.")

    args = p.parse_args(rest)

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
