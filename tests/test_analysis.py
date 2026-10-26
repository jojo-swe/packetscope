from packetscope import analyze


def test_detects_retransmissions_and_dns_failures() -> None:
    report = analyze([
        {"src":"a","dst":"b","protocol":"tcp","packets":100,"bytes":50000,"retransmissions":8},
        {"src":"a","dst":"dns","protocol":"dns","queries":20,"dns_failures":5,"bytes":1000},
    ])
    codes = {finding["code"] for finding in report["findings"]}
    assert {"tcp_retransmissions", "dns_failures"} <= codes
    assert report["highest_severity"] == "high"


def test_detects_asymmetry_and_denies() -> None:
    report = analyze([
        {"src":"a","dst":"b","protocol":"tcp","packets":10,"bytes":100000,"action":"allow"},
        {"src":"b","dst":"a","protocol":"tcp","packets":2,"bytes":1000,"action":"deny"},
    ])
    codes = {finding["code"] for finding in report["findings"]}
    assert "traffic_asymmetry" in codes
    assert "high_deny_rate" in codes


def test_clean_traffic_has_no_findings() -> None:
    report = analyze([
        {"src":"a","dst":"b","protocol":"tcp","packets":1000,"bytes":50000,"retransmissions":1},
        {"src":"b","dst":"a","protocol":"tcp","packets":900,"bytes":45000,"retransmissions":0},
    ])
    assert report["findings"] == []
    assert report["highest_severity"] == "info"


def test_detects_deny_fanout() -> None:
    report = analyze([
        {"src": "s", "dst": "t", "dst_port": port, "action": "deny"} for port in range(12)
    ])
    fanout = [finding for finding in report["findings"] if finding["code"] == "deny_fanout"]
    assert len(fanout) == 1
    assert fanout[0]["severity"] == "medium"
    assert fanout[0]["evidence"] == {"source": "s", "distinct_targets": 12, "denied_flows": 12}


def test_repeated_denies_to_one_target_are_not_fanout() -> None:
    report = analyze([{"src": "s", "dst": "t", "dst_port": 22, "action": "deny"}] * 12)
    assert "deny_fanout" not in {finding["code"] for finding in report["findings"]}
