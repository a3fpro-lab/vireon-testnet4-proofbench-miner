from __future__ import annotations

from vireon_miner.stratum import StratumMsg, parse_json_line


def test_bench_stratum_encode(benchmark):
    msg = StratumMsg("mining.submit", ["u.worker", "jobid", "extranonce2", "ntime", "nonce"], msg_id=4)
    benchmark(msg.to_json_line)


def test_bench_stratum_parse(benchmark):
    line = StratumMsg("mining.notify", ["job", "x", "y"], msg_id=None).to_json_line()
    benchmark(parse_json_line, line)
