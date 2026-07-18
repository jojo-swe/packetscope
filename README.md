# PacketScope

PacketScope turns portable JSON, JSONL, or NDJSON flow records into explainable network findings.

It is designed for incident triage, sanitized capture review, lab exercises, CI regression checks, and pipelines fed by tools such as Zeek or tshark.

## What it detects

- elevated TCP retransmission ratios
- elevated DNS failure rates
- strong directional traffic asymmetry
- unusually high proportions of denied or dropped flows
- top talkers and protocol distribution

Every finding includes severity, evidence, and a recommended next troubleshooting step.

## Quick start

```bash
pip install -e ".[dev]"
packetscope examples/incident-flows.json
```

Machine-readable output:

```bash
packetscope examples/incident-flows.json --json
```

Fail a CI job when findings reach a threshold:

```bash
packetscope flows.ndjson --fail-on medium
```

Exit codes:

- `0`: no finding reached the configured threshold
- `1`: threshold reached
- `2`: invalid input or arguments

## Input

PacketScope accepts:

- a JSON array of flow objects
- `{ "flows": [...] }`
- one JSON object per line in `.jsonl` or `.ndjson`

Common fields include `src`, `dst`, `protocol`, `packets`, `bytes`, `retransmissions`, `queries`, `dns_failures`, `dst_port`, and `action`.

## Python API

```python
from packetscope import analyze

report = analyze([
    {"src": "10.0.0.10", "dst": "203.0.113.5", "protocol": "tcp", "packets": 1000, "retransmissions": 60}
])
print(report["findings"])
```

## Portfolio value

PacketScope demonstrates protocol-aware analytics, deterministic heuristics, explainable findings, portable data ingestion, CLI design, testing, and CI integration without requiring proprietary packet-capture tooling.
