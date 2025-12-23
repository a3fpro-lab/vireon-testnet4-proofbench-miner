import json
import time
import platform
import sys

from vireon_miner.scan_auto import find_share_bounded_auto


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

    # Warm up (Numba compile happens here if available, not inside timing)
    _ = find_share_bounded_auto(header76, target_int, start_nonce=0, count=1)

    t0 = time.time()

    for i in range(batches):
        start_nonce = i * batch_size
        scan = find_share_bounded_auto(header76, target_int, start_nonce=start_nonce, count=batch_size)
        trials += batch_size
        if scan is not None:
            found += 1
            backend = scan.backend

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
