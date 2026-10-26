import json
from pathlib import Path

from packetscope.cli import main

EXAMPLE = str(Path(__file__).parent.parent / "examples" / "incident-flows.json")


def test_json_output_and_exit_codes(capsys) -> None:
    assert main([EXAMPLE, "--json", "--fail-on", "critical"]) == 0
    assert json.loads(capsys.readouterr().out)["highest_severity"] == "high"
    assert main([EXAMPLE, "--fail-on", "high"]) == 1
    assert "Findings:" in capsys.readouterr().out


def test_loads_jsonl(tmp_path, capsys) -> None:
    path = tmp_path / "flows.jsonl"
    path.write_text('{"src": "a", "protocol": "tcp"}\n\n{"src": "b", "protocol": "udp"}\n')
    assert main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["flow_count"] == 2
