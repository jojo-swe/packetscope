# PacketScope

![CI](https://github.com/jojo-swe/packetscope/actions/workflows/ci.yml/badge.svg)

PacketScope turns portable JSON, JSONL, or NDJSON flow records into explainable network findings.

It is designed for incident triage, sanitized capture review, lab exercises, CI regression checks, and pipelines fed by any tool that can emit the [input fields](#input) below.

## What it detects

- elevated TCP retransmission ratios (`tcp_retransmissions`)
- elevated DNS failure rates (`dns_failures`)
- strong directional traffic asymmetry (`traffic_asymmetry`)
- unusually high proportions of denied or dropped flows (`high_deny_rate`)
- one source whose denied flows fan out to many targets, e.g. a scan (`deny_fanout`)
- top talkers and protocol distribution

Every finding includes severity, evidence, and a recommended next troubleshooting step.

### Thresholds

| Code | Triggers when | Severity |
| --- | --- | --- |
| `tcp_retransmissions` | retransmissions / TCP packets ≥ 0.02 | medium; high at ≥ 0.05 |
| `dns_failures` | DNS failures / DNS queries ≥ 0.05 | medium; high at ≥ 0.20 |
| `traffic_asymmetry` | pair total ≥ 10 000 bytes and larger / smaller direction ≥ 20 | medium |
| `high_deny_rate` | denied flows / all flows ≥ 0.10 | medium |
| `deny_fanout` | denied flows from one `src` reach ≥ 10 distinct `dst`/`dst_port` pairs | medium; high at ≥ 50 |

A flow counts as DNS when `protocol` is `dns` or `dst_port` is 53; without a `queries` field it counts as one query. A flow counts as denied when `action` is `deny`, `denied`, `drop`, or `blocked`.

## Quick start

```bash
pip install -e ".[dev]"
packetscope examples/incident-flows.json --fail-on critical
```

`--fail-on` defaults to `high`, so without the flag this command exits `1`: the bundled example contains high findings on purpose.

```text
Flows: 15
Highest severity: high
Protocols: dns=1, tcp=14
Top talkers:
  10.0.10.25: 912000 bytes
  203.0.113.10: 18000 bytes
  10.0.20.99: 5200 bytes
Findings:
  [HIGH] Elevated DNS failure rate (dns_failures)
    Evidence: {"failures": 24, "queries": 100, "ratio": 0.24}
    Action: Check resolver reachability, SERVFAIL/NXDOMAIN sources, forwarding rules, and upstream latency.
  [HIGH] Elevated TCP retransmissions (tcp_retransmissions)
    Evidence: {"ratio": 0.0578, "retransmissions": 67, "tcp_packets": 1160}
    Action: Inspect loss, duplex, MTU, congestion, and overloaded endpoints along the affected path.
  [MEDIUM] Denied connections from 10.0.20.99 fan out to 12 targets (deny_fanout)
    Evidence: {"denied_flows": 12, "distinct_targets": 12, "source": "10.0.20.99"}
    Action: Treat as a probable scan or misconfigured client; check the source host and block or rate-limit at the edge.
  [MEDIUM] High proportion of denied flows (high_deny_rate)
    Evidence: {"denied_flows": 12, "flow_count": 15, "ratio": 0.8}
    Action: Group denies by source, destination and port to distinguish policy mistakes from scans or unwanted traffic.
  [MEDIUM] Strong traffic asymmetry between 10.0.0.53 and 10.0.10.25 (traffic_asymmetry)
    Evidence: {"bytes_a_to_b": 0, "bytes_b_to_a": 12000, "endpoint_a": "10.0.0.53", "endpoint_b": "10.0.10.25"}
    Action: Verify expected application behaviour, return routing, stateful firewall paths, and packet capture placement.
  [MEDIUM] Strong traffic asymmetry between 10.0.10.25 and 203.0.113.10 (traffic_asymmetry)
    Evidence: {"bytes_a_to_b": 900000, "bytes_b_to_a": 18000, "endpoint_a": "10.0.10.25", "endpoint_b": "203.0.113.10"}
    Action: Verify expected application behaviour, return routing, stateful firewall paths, and packet capture placement.
```

Machine-readable output (keys are sorted, so reports diff cleanly):

```bash
packetscope examples/incident-flows.json --json --fail-on critical
```

```json
{
  "findings": [
    {
      "code": "dns_failures",
      "evidence": {"failures": 24, "queries": 100, "ratio": 0.24},
      "recommendation": "Check resolver reachability, SERVFAIL/NXDOMAIN sources, forwarding rules, and upstream latency.",
      "severity": "high",
      "title": "Elevated DNS failure rate"
    }
  ],
  "flow_count": 15,
  "highest_severity": "high",
  "protocols": {"dns": 1, "tcp": 14},
  "top_talkers": [{"bytes": 912000, "source": "10.0.10.25"}]
}
```

(Trimmed: the real output lists every finding and up to five top talkers.)

Read from a pipe with `-`, and fail a CI job when findings reach a threshold:

```bash
cat flows.ndjson | packetscope - --fail-on medium
```

Exit codes:

- `0`: no finding reached the `--fail-on` threshold (default `high`)
- `1`: threshold reached
- `2`: invalid input or arguments

## Input

PacketScope accepts a file path, or `-` for stdin, containing:

- a JSON array of flow objects
- `{ "flows": [...] }`
- one JSON object per line (JSONL / NDJSON)

The format is detected from the content, not the file name. Every record must be a JSON object; anything else exits `2`.

Fields read from each record (all optional):

| Field | Type | Default | Used for |
| --- | --- | --- | --- |
| `src` | string | `"unknown"` | top talkers, asymmetry, deny fan-out |
| `dst` | string | `"unknown"` | asymmetry, deny fan-out |
| `protocol` | string, lower-cased | `"unknown"` | protocol counts; `tcp` and `dns` heuristics |
| `packets` | number | `0` | TCP retransmission ratio |
| `bytes` | number | `0` | top talkers, asymmetry |
| `retransmissions` | number | `0` | TCP retransmission ratio |
| `queries` | number | `1` for DNS flows | DNS failure ratio |
| `dns_failures` | number | `0` | DNS failure ratio |
| `dst_port` | number | `0` | DNS detection (53), deny fan-out |
| `action` | string | `""` | deny rate, deny fan-out |

Numeric fields that are missing, `null`, or not numbers are treated as `0` without a warning.

### Known limitations

- **One-directional records look asymmetric.** Each record's `bytes` is counted in the `src → dst` direction only. A record whose reverse direction is absent therefore always triggers `traffic_asymmetry` once it exceeds 10 000 bytes; the DNS flow `10.0.10.25 → 10.0.0.53` in the bundled example is flagged for this reason. Sources that see both directions should emit one record per direction.
- **No native Zeek or tshark field names.** Fields such as Zeek's `id.orig_h`, `id.resp_h`, `orig_bytes`, or `resp_bytes` are not recognised; rename them to the fields above first.

## Python API

`Finding` and `analyze` are exported from `packetscope`:

```python
from packetscope import analyze

report = analyze([
    {"src": "10.0.0.10", "dst": "203.0.113.5", "protocol": "tcp", "packets": 1000, "retransmissions": 60}
])
print(report["findings"])
```

`analyze` returns the same dictionary the CLI prints with `--json`.

## Development

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check .
```

PacketScope shows deterministic, explainable flow heuristics without needing proprietary packet-capture tooling.

## License

Apache-2.0. See [LICENSE](LICENSE).
