from packetscope import analyze


def test_summary_counts_protocols_and_talkers() -> None:
    result = analyze([
        {"src": "10.x.z.y", "protocol": "tcp", "bytes": 100},
        {"src": "10.x.z.y", "protocol": "udp", "bytes": 100},
    ])
    assert result["flow_count"] == 2
    assert result["protocols"] == {"tcp": 1, "udp": 1}
    assert result["top_talkers"][0] == {"source": "10.x.z.y", "bytes": 200}
