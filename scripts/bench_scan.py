import json
import time
import platform
import sys

from vireon_miner.scan import find_share_bounded

def main():
    header76 = b"\x01" * 76

    # Easy-but-not-trivial target for speed test
    target_int = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

    batches = 5
    batch_size = 20000  # 100k total hashes (fast on GitHub runner)
    trials = 0
    found = 0

    t0 = time.time()
    for i in range(batches):
        res = find_share_bounded(header76, target_int, start_nonce=i * batch_size, count=batch_size)
        trials += batch_size
        if res is not None:
            found += 1
    dt = max(1e-9, time.time() - t0)
    mhps = (trials / dt) / 1e6

    out = {
        "trials": trials,
        "seconds": dt,
        "mhps": mhps,
        "found_batches": found,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }

    print(json.dumps(out, indent=2))
    with open("results/bench_scan.json", "w") as f:
        json.dump(out, f, indent=2)

    # Hard fail if something is wildly broken
    if mhps <= 0:
        raise SystemExit("bench invalid: mhps <= 0")

if __name__ == "__main__":
    main()
