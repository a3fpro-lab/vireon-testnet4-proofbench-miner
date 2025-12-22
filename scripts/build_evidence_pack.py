from __future__ import annotations

import json
import os
from pathlib import Path
from datetime import datetime, timezone


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def main() -> int:
    out_dir = Path("results")
    out_dir.mkdir(parents=True, exist_ok=True)

    bench = _load_json(out_dir / "bench.json")
    mach = _load_json(out_dir / "machine.json")

    sha = os.environ.get("GITHUB_SHA", "local")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    now = datetime.now(timezone.utc).isoformat()

    highlights = []
    for b in bench.get("benchmarks", []):
        name = b.get("name")
        mean = b.get("stats", {}).get("mean")
        if name and mean is not None:
            highlights.append((name, mean))

    md = []
    md.append("# EVIDENCE PACK\n\n")
    md.append(f"- UTC generated: `{now}`\n")
    md.append(f"- Commit: `{sha}`\n")
    md.append(f"- Run ID: `{run_id}`\n\n")

    md.append("## Machine\n")
    if mach:
        for k, v in mach.items():
            md.append(f"- {k}: `{v}`\n")
    else:
        md.append("- (missing machine.json)\n")
    md.append("\n")

    md.append("## Benchmarks (raw JSON is authoritative)\n")
    if highlights:
        for name, mean in highlights:
            md.append(f"- {name}: mean `{mean}` seconds\n")
    else:
        md.append("- (missing bench.json or no benchmarks)\n")
    md.append("\n")

    md.append("## Reproduce\n")
    md.append("```bash\n")
    md.append("pip install -e .\n")
    md.append("pip install pytest pytest-benchmark\n")
    md.append("python scripts/machine_info.py\n")
    md.append("pytest -q\n")
    md.append("pytest -q --benchmark-only --benchmark-json results/bench.json benches/\n")
    md.append("python scripts/build_evidence_pack.py\n")
    md.append("```\n")

    (out_dir / "EVIDENCE_PACK.md").write_text("".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
