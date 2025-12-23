from vireon_miner.scan_auto import find_share_bounded_auto

# warmup (so JIT compile doesn't pollute timing)
_ = find_share_bounded_auto(header76, target_int, start_nonce=0, count=1)

backend = "python"
for i in range(batches):
    start_nonce = i * batch_size
    res = find_share_bounded_auto(header76, target_int, start_nonce=start_nonce, count=batch_size)
    trials += batch_size
    if res is not None:
        found += 1
        backend = res.backend

out["backend"] = backend
