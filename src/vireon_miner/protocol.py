from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class StratumParseError(RuntimeError):
    pass


@dataclass(frozen=True)
class SubscribeInfo:
    extranonce1_hex: str
    extranonce2_size: int


def parse_subscribe_reply(reply: dict[str, Any]) -> SubscribeInfo:
    """
    Typical Stratum subscribe reply:
    {"id":1,"result":[[...subscriptions...],"extranonce1",extranonce2_size],"error":null}
    """
    if "result" not in reply:
        raise StratumParseError("missing result in subscribe reply")
    res = reply["result"]

    if isinstance(res, list) and len(res) >= 3:
        extranonce1 = res[1]
        extranonce2_size = res[2]
        if not isinstance(extranonce1, str) or not isinstance(extranonce2_size, int):
            raise StratumParseError("subscribe reply types invalid")
        return SubscribeInfo(extranonce1_hex=extranonce1, extranonce2_size=extranonce2_size)

    raise StratumParseError("unsupported subscribe reply format")


def is_method(msg: dict[str, Any], method: str) -> bool:
    return msg.get("method") == method and "params" in msg
