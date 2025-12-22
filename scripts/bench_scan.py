import json
import time
import platform
import sys

# Safe import: never let bench die because numba path is missing/broken
try:
    from vireon_miner.fastscan_numba import available as numba_available, find_share_bounded_numba
except Exception:
    def numba_available() -> bool:  # type: ignore
        return False

    def find_share_bounded_numba(*args, **kwargs):  # type: ignore
        return None

from vireon_miner.scan import find_share_bounded as find_share_bounded_py


def main():
    # Deterministic dummy header (76 bytes)
    header76 = b"\x01" * 76

    # Easy target so we find “shares” quickly (proofbench, not real mining difficulty)
    target_int = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

    batches = 5
    batch_size = 20000  # 100k total hashes (fast on GitHub runner)

    trials = 0
    found = 0
    backend = "python"

    t0 = time.time()

    for i in range(batches):
        start_nonce = i * batch_size

        if numba_available():
            backend = "numba-midstate"
            nonce = find_share_bounded_numba(
                header76,
                target_int,
                start_nonce=start_nonce,
                count=batch_size,
            )
            # We only need to know "found something" for the bench counter
            res_found = (nonce is not None)
        else:
            res = find_share_bounded_py(
                header76,
                target_int,
                start_nonce=start_nonce,
                count=batch_size,
            )
            res_found = (res is not None)

        trials += batch_size
        if res_found:
            found += 1

    dt = max(1e-9, time.time() - t0)
    mhps = (trials / dt) / 1e6

    out = {
        "backend": backend,
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

    if mhps <= 0:
        raise SystemExit("bench invalid: mhps <= 0")


if __name__ == "__main__":
    main()
