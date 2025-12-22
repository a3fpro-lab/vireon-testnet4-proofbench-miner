from vireon_miner.hashing import sha256d


def test_sha256d_vectors():
    # 80 bytes of zeros
    assert sha256d(b"\x00" * 80).hex() == "4be7570e8f70eb093640c8468274ba759745a7aa2b7d25ab1e0421b259845014"

    # 0..79
    assert sha256d(bytes(range(80))).hex() == "852c98044fb00507122ff63bda7b529566348fc204f72b00dff1afd7b40501e4"
