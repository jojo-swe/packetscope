from packetscope import summarize

def test_summary_counts_protocols_and_talkers() -> None:
    result=summarize([{"src":"10.0.0.1","protocol":"tcp"},{"src":"10.0.0.1","protocol":"udp"}])
    assert result["flow_count"] == 2
    assert result["top_talkers"][0] == ("10.0.0.1",2)
