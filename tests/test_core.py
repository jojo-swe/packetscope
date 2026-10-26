from packetscope import summarize


def test_summary_counts_protocols_and_talkers() -> None:
    result = summarize([
        {"src": "10.0.0.1", "protocol": "tcp", "bytes": 100},
        {"src": "10.0.0.1", "protocol": "udp", "bytes": 100},
    ])
    assert result["flow_count"] == 2
    assert result["protocols"] == {"tcp": 1, "udp": 1}
    assert result["top_talkers"][0] == {"source": "10.0.0.1", "bytes": 200}
