from vireon_miner.job import merkle_root_le, build_header_80
from vireon_miner.hashing import sha256d


def test_merkle_root_le_and_header_hash_known():
    # Deterministic synthetic Stratum-like pieces
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

    # Expected merkle root (little-endian) for the above synthetic components
    assert mr_le.hex() == "952342ad97a763a8ac60da98b45ff440f0d747dfe8c0581b8b8aa7229ab89b4f"

    header = build_header_80(
        version_hex="20000000",
        prevhash_hex="aa" * 32,
        merkle_root_le_bytes=mr_le,
        ntime_hex="5f5e1000",
        nbits_hex="1d00ffff",
        nonce_hex="00000001",
    )

    assert len(header) == 80
    assert sha256d(header).hex() == "d3cf04a015986aa2f9bf4514a2472deebf3a3e324fbe7877552cb39d7a407c1a"
