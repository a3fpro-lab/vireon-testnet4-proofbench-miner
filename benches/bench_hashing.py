from __future__ import annotations

from vireon_miner.hashing import sha256d


def test_bench_sha256d_80bytes(benchmark):
    data = b"\x00" * 80
    benchmark(sha256d, data)


def test_bench_sha256d_nonce_scan_like(benchmark):
    data = bytearray(b"\x00" * 80)

    def work():
        # mutate 4 bytes like a nonce update (loop realism)
        data[76] = (data[76] + 1) & 0xFF
        data[77] = (data[77] + 1) & 0xFF
        data[78] = (data[78] + 1) & 0xFF
        data[79] = (data[79] + 1) & 0xFF
        sha256d(bytes(data))

    benchmark(work)
