```md
# Evidence Standard

A performance or correctness claim is accepted only if backed by:

- `results/bench.json` — benchmark raw output (authoritative)
- `results/machine.json` — hardware/software provenance
- `results/EVIDENCE_PACK.md` — human-readable summary + repro steps
- the exact commit hash that produced the artifact

CI uploads `results/` as an artifact in the **Bench** workflow
