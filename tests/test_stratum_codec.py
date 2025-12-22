from vireon_miner.stratum import StratumMsg, parse_json_line


def test_stratum_msg_roundtrip_shape():
    b = StratumMsg("mining.subscribe", ["vireon/0.1"], msg_id=1).to_json_line()
    obj = parse_json_line(b)
    assert obj["id"] == 1
    assert obj["method"] == "mining.subscribe"
    assert obj["params"] == ["vireon/0.1"]
