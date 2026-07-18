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
