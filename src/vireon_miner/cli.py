from __future__ import annotations

import argparse
import sys

from .hashing import sha256d
from .stratum import StratumMsg


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vireon-miner")
    p.add_argument("--echo", action="store_true", help="Print sample Stratum message and exit.")
    p.add_argument("--selftest", action="store_true", help="Run a tiny local hash self-test and exit.")
    args = p.parse_args(argv)

    if args.echo:
        msg = StratumMsg("mining.subscribe", ["vireon/0.1"], msg_id=1)
        sys.stdout.buffer.write(msg.to_json_line())
        return 0

    if args.selftest:
        d = sha256d(b"\x00" * 80).hex()
        print(d)
        return 0

    print("Scaffold OK. Next: add live Stratum miner loop.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
