from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .core import analyze

_LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".ndjson", ".jsonl"}:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    payload = json.loads(text)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("flows"), list):
        return payload["flows"]
    raise ValueError("input must be a JSON array, {'flows': [...]}, JSONL, or NDJSON")


def render(report: dict[str, Any]) -> str:
    lines = [
        f"Flows: {report['flow_count']}",
        f"Highest severity: {report['highest_severity']}",
        "Protocols: " + ", ".join(f"{key}={value}" for key, value in report["protocols"].items()),
    ]
    if report["top_talkers"]:
        lines.append("Top talkers:")
        lines.extend(f"  {item['source']}: {item['bytes']} bytes" for item in report["top_talkers"])
    if not report["findings"]:
        lines.append("No notable findings.")
    else:
        lines.append("Findings:")
        for finding in report["findings"]:
            lines.append(f"  [{finding['severity'].upper()}] {finding['title']} ({finding['code']})")
            lines.append(f"    Evidence: {json.dumps(finding['evidence'], sort_keys=True)}")
            lines.append(f"    Action: {finding['recommendation']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explain packet and flow anomalies from JSON records")
    parser.add_argument("input", type=Path)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--fail-on", choices=tuple(_LEVEL), default="high")
    args = parser.parse_args(argv)

    try:
        report = analyze(load_records(args.input))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return 2

    print(json.dumps(report, indent=2, sort_keys=True) if args.json_output else render(report))
    return int(_LEVEL[report["highest_severity"]] >= _LEVEL[args.fail_on])


if __name__ == "__main__":
    raise SystemExit(main())
