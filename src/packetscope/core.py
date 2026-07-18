from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Any

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    evidence: dict[str, Any]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _number(flow: dict[str, Any], key: str) -> float:
    value = flow.get(key, 0)
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def analyze(flows: list[dict[str, Any]]) -> dict[str, Any]:
    protocols = Counter(str(flow.get("protocol", "unknown")).lower() for flow in flows)
    talker_bytes: Counter[str] = Counter()
    pair_directions: dict[tuple[str, str], list[float]] = defaultdict(lambda: [0.0, 0.0])
    findings: list[Finding] = []

    retransmissions = 0.0
    tcp_packets = 0.0
    dns_queries = 0.0
    dns_failures = 0.0
    denied = 0

    for flow in flows:
        src = str(flow.get("src", "unknown"))
        dst = str(flow.get("dst", "unknown"))
        byte_count = _number(flow, "bytes")
        talker_bytes[src] += int(byte_count)

        ordered = tuple(sorted((src, dst)))
        direction = 0 if (src, dst) == ordered else 1
        pair_directions[ordered][direction] += byte_count

        protocol = str(flow.get("protocol", "unknown")).lower()
        if protocol == "tcp":
            tcp_packets += _number(flow, "packets")
            retransmissions += _number(flow, "retransmissions")
        if protocol == "dns" or int(_number(flow, "dst_port")) == 53:
            dns_queries += _number(flow, "queries") or 1
            dns_failures += _number(flow, "dns_failures")
        if str(flow.get("action", "")).lower() in {"deny", "denied", "drop", "blocked"}:
            denied += 1

    if tcp_packets and retransmissions / tcp_packets >= 0.02:
        ratio = retransmissions / tcp_packets
        findings.append(Finding(
            "tcp_retransmissions", "high" if ratio >= 0.05 else "medium",
            "Elevated TCP retransmissions",
            {"retransmissions": int(retransmissions), "tcp_packets": int(tcp_packets), "ratio": round(ratio, 4)},
            "Inspect loss, duplex, MTU, congestion, and overloaded endpoints along the affected path.",
        ))

    if dns_queries and dns_failures / dns_queries >= 0.05:
        ratio = dns_failures / dns_queries
        findings.append(Finding(
            "dns_failures", "high" if ratio >= 0.2 else "medium",
            "Elevated DNS failure rate",
            {"queries": int(dns_queries), "failures": int(dns_failures), "ratio": round(ratio, 4)},
            "Check resolver reachability, SERVFAIL/NXDOMAIN sources, forwarding rules, and upstream latency.",
        ))

    for (a, b), (forward, reverse) in pair_directions.items():
        total = forward + reverse
        if total < 10_000:
            continue
        smaller = min(forward, reverse)
        ratio = (max(forward, reverse) / smaller) if smaller else float("inf")
        if ratio >= 20:
            findings.append(Finding(
                "traffic_asymmetry", "medium",
                f"Strong traffic asymmetry between {a} and {b}",
                {"endpoint_a": a, "endpoint_b": b, "bytes_a_to_b": int(forward), "bytes_b_to_a": int(reverse)},
                "Verify expected application behaviour, return routing, stateful firewall paths, and packet capture placement.",
            ))

    if flows and denied / len(flows) >= 0.1:
        findings.append(Finding(
            "high_deny_rate", "medium",
            "High proportion of denied flows",
            {"denied_flows": denied, "flow_count": len(flows), "ratio": round(denied / len(flows), 4)},
            "Group denies by source, destination and port to distinguish policy mistakes from scans or unwanted traffic.",
        ))

    findings.sort(key=lambda item: (-_SEVERITY[item.severity], item.code, item.title))
    highest = max((finding.severity for finding in findings), key=lambda value: _SEVERITY[value], default="info")
    return {
        "flow_count": len(flows),
        "protocols": dict(sorted(protocols.items())),
        "top_talkers": [{"source": src, "bytes": count} for src, count in talker_bytes.most_common(5)],
        "highest_severity": highest,
        "findings": [finding.to_dict() for finding in findings],
    }


def summarize(flows: list[dict[str, Any]]) -> dict[str, Any]:
    return analyze(flows)
