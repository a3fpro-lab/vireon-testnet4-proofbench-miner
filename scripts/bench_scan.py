import json
import time

from vireon_miner.scan import find_share_bounded

def main():
    # Deterministic dummy header (76 bytes)
    header76 = b"\x01" * 76

    # Easy target so we actually find a “share” quickly
    # (Not real difficulty; this is a proofbench speed test.)
    target_int = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

    start = time.time()
    trials = 0
    found = 0

    # Scan a few batches; record throughput
    for i in range(10):
        res = find_share_bounded(header76, target_int, start_nonce=i * 100000, count=100000)
        trials += 100000
        if res is not None:
            found += 1

    dt = time.time() - start
    mhps = (trials / dt) / 1e6

    out = {
        "trials": trials,
        "seconds": dt,
        "mhps": mhps,
        "found_batches": found,
    }

    print(json.dumps(out, indent=2))
    with open("results/bench_scan.json", "w") as f:
        json.dump(out, f, indent=2)

if __name__ == "__main__":
    main()
