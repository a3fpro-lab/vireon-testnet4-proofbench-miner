from __future__ import annotations

from vireon_miner.job import merkle_root_le, build_header_80, header_hash_int_le


def test_bench_build_and_hash_header(benchmark):
    coinb1_hex = "0200000001"
    coinb2_hex = "ffffffff"
    extranonce1_hex = "01020304"
    extranonce2_hex = "00000000"
    merkle_branch_hex = ["11" * 32, "22" * 32]

    mr_le = merkle_root_le(
        coinb1_hex=coinb1_hex,
        coinb2_hex=coinb2_hex,
        extranonce1_hex=extranonce1_hex,
        extranonce2_hex=extranonce2_hex,
        merkle_branch_hex=merkle_branch_hex,
    )

    def work():
        hdr = build_header_80(
            version_hex="20000000",
            prevhash_hex="aa" * 32,
            merkle_root_le_bytes=mr_le,
            ntime_hex="5f5e1000",
            nbits_hex="1d00ffff",
            nonce_hex="00000001",
        )
        header_hash_int_le(hdr)

    benchmark(work)
