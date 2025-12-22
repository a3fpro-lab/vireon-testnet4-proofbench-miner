# Vireon Testnet4 ProofBench Miner

A **real Stratum miner script** scaffold that is hard to question because it is:

- **Correctness-tested** (hard SHA256d vectors + Stratum codec tests)
- **Benchmarked** (hashing throughput + codec overhead)
- **Evidence-packed** (`bench.json` + `machine.json` + generated `EVIDENCE_PACK.md`)
- **CI-proven** (tests on every push, benchmarks on demand + weekly)

## Quick start (CI does the proof)
Push commits from Safari; GitHub Actions runs:
- **CI**: unit tests
- **Bench**: benchmarks + evidence artifact upload

## Run locally (optional)
```bash
pip install -e .
pip install pytest pytest-benchmark
pytest -q
python scripts/machine_info.py
pytest -q --benchmark-only --benchmark-json results/bench.json benches/
python scripts/build_evidence_pack.py


Smoke
vireon-miner --echo
vireon-miner --selftest

Evidence
See:
	•	BENCHMARKS.md
	•	EVIDENCE.md
	•	results/ artifact attached to the Bench workflow run


