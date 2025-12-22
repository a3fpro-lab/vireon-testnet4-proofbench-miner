from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path


def main() -> int:
    out_dir = Path("results")
    out_dir.mkdir(parents=True, exist_ok=True)

    info = {
        "python_version": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
    }

    (out_dir / "machine.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
