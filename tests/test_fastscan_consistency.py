import os
import pytest

from vireon_miner.scan import find_share_bounded as find_py

numba = pytest.importorskip("numba")  # skip test if numba not installed

from vireon_miner.fastscan_numba import find_share_bounded_numba, available as numba_available


def test_numba_matches_python_on_easy_target():
    if not numba_available():
        pytest.skip("numba backend not available")

    header76 = b"\x01" * 76
    target_int = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

    # Same nonce range should either find the same nonce or both find none
    start = 0
    count = 5000

    py = find_py(header76, target_int, start_nonce=start, count=count)
    nb = find_share_bounded_numba(header76, target_int, start_nonce=start, count=count)

    if py is None:
        assert nb is None
    else:
        assert nb is not None
        assert int(nb) == int(py.nonce)
