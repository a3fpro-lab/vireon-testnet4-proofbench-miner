from vireon_miner.fastscan_numba import available as numba_available, find_share_bounded_numba
from vireon_miner.scan import find_share_bounded as find_share_bounded_py

backend = "python"

# ...
for i in range(batches):
    start_nonce = i * batch_size
    if numba_available():
        backend = "numba-midstate"
        nonce = find_share_bounded_numba(header76, target_int, start_nonce=start_nonce, count=batch_size)
        res = None if nonce is None else True
    else:
        res = find_share_bounded_py(header76, target_int, start_nonce=start_nonce, count=batch_size)
    trials += batch_size
    if res is not None:
        found += 1

out["backend"] = backend
