# Working on PacketScope

## Layout

- `src/packetscope/core.py`: heuristics, `Finding`, `analyze`
- `src/packetscope/cli.py`: `load_records`, `render`, `main`
- `tests/`: `test_analysis.py` (heuristics), `test_cli.py` (CLI), `test_core.py` (report shape)
- `examples/incident-flows.json`: bundled example, used by CI as a smoke test
- `.github/workflows/ci.yml`: ruff, pytest and the smoke test on Python 3.11–3.13

## Setup and commands

```bash
pip install -e ".[dev]"
pytest              # pythonpath = ["src"] in pyproject.toml, so no install is strictly needed
ruff check .
packetscope examples/incident-flows.json --fail-on critical
```

## Conventions

- Python ≥ 3.11, `from __future__ import annotations`, standard library only (no runtime deps).
- Line length 100; ruff rules `E`, `F`, `I`, `W` (set in `pyproject.toml`).
- Severity order lives in one place, `core._SEVERITY`; the CLI imports it.

## Adding a heuristic

1. Accumulate inside the single loop in `analyze`; put threshold constants next to `_SEVERITY`.
2. Append a `Finding(code, severity, title, evidence, recommendation)` after the loop.
3. Keep `evidence` JSON-serialisable, with `int` or rounded `float` values.
4. Add a positive and a negative test in `tests/test_analysis.py` with minimal flow lists.
5. Extend `examples/incident-flows.json` if the smoke test should show it; update the README tables.

## CLI contract and don'ts

- Exit codes: `0` below `--fail-on`, `1` threshold reached, `2` invalid input or arguments.
- `--json` output must stay `sort_keys=True` so reports are diffable.
- No new dependencies, no network access, no pcap parsing.
- Do not change finding `code` strings without updating the README and tests.
