# Benchmarks

This repo benchmarks miner-critical primitives:

1) **Hashing kernel**: double-SHA256 on 80-byte inputs (Bitcoin header size)
2) **Stratum codec**: JSON line encode/decode overhead

## Protocol
- Benchmarks use `pytest-benchmark`
- Raw output is exported to `results/bench.json` (authoritative)
- Machine metadata is exported to `results/machine.json`
- `results/EVIDENCE_PACK.md` is generated from those files

## Run locally (optional)
```bash
pip install -e .
pip install pytest pytest-benchmark
python scripts/machine_info.py
pytest -q
pytest -q --benchmark-only --benchmark-json results/bench.json benches/
python scripts/build_evidence_pack.py
