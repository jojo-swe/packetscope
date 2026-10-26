import io
import json
from pathlib import Path

import pytest

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


def test_reads_ndjson_from_stdin(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO('{"src": "a"}\n{"src": "b"}\n'))
    assert main(["-", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["flow_count"] == 2


def test_ndjson_in_json_suffix_is_detected(tmp_path, capsys) -> None:
    path = tmp_path / "flows.json"
    path.write_text('{"src": "a"}\n')
    assert main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["flow_count"] == 1


@pytest.mark.parametrize("text", ['[{"src": "a"}, 3]', '{"src": "a"}\n[1]\n', "42", "{bad"])
def test_invalid_records_exit_2(monkeypatch, text) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    with pytest.raises(SystemExit) as exc:
        main(["-"])
    assert exc.value.code == 2
