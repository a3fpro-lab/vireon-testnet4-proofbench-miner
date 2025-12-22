from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StratumMsg:
    method: str
    params: list[Any]
    msg_id: int | None = None

    def to_json_line(self) -> bytes:
        obj = {"id": self.msg_id, "method": self.method, "params": self.params}
        return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def parse_json_line(line: bytes) -> dict[str, Any]:
    return json.loads(line.decode("utf-8").strip())
