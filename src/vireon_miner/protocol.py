from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SubscribeInfo:
    """
    Parsed result of mining.subscribe.

    Stratum v1 response format (typical):
      {
        "id": 1,
        "result": [
          [["mining.set_difficulty", "deadbeef"], ["mining.notify", "cafebabe"]],
          "extranonce1_hex_or_ascii",
          extranonce2_size_int
        ],
        "error": null
      }
    """
    subscriptions: List[Tuple[str, str]]
    extranonce1: str
    extranonce2_size: int


def is_method(msg: Dict[str, Any], method: str) -> bool:
    """True if this JSON-RPC message is a notification with the given method."""
    return msg.get("method") == method


def parse_subscribe_reply(reply: Dict[str, Any]) -> SubscribeInfo:
    """
    Parse a mining.subscribe reply. Raises ValueError on unexpected structure.
    """
    if not isinstance(reply, dict):
        raise ValueError("subscribe reply must be a dict")

    err = reply.get("error")
    if err:
        raise ValueError(f"subscribe error: {err}")

    result = reply.get("result")
    if not isinstance(result, list) or len(result) < 3:
        raise ValueError(f"unexpected subscribe result: {result!r}")

    subs_raw = result[0]
    extranonce1 = result[1]
    extranonce2_size = result[2]

    if not isinstance(subs_raw, list):
        raise ValueError(f"unexpected subscriptions field: {subs_raw!r}")
    if not isinstance(extranonce1, str):
        raise ValueError(f"unexpected extranonce1 type: {type(extranonce1)}")
    if not isinstance(extranonce2_size, int):
        raise ValueError(f"unexpected extranonce2_size type: {type(extranonce2_size)}")

    subs: List[Tuple[str, str]] = []
    for item in subs_raw:
        # item is usually [method_name, subscription_id]
        if isinstance(item, list) and len(item) >= 2 and isinstance(item[0], str) and isinstance(item[1], str):
            subs.append((item[0], item[1]))
        else:
            # tolerate weird shapes but keep deterministic behavior
            raise ValueError(f"unexpected subscription entry: {item!r}")

    return SubscribeInfo(subscriptions=subs, extranonce1=extranonce1, extranonce2_size=extranonce2_size)
