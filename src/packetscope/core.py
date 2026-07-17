from __future__ import annotations
from collections import Counter

def summarize(flows: list[dict]) -> dict:
    protocols=Counter(flow.get("protocol","unknown") for flow in flows)
    talkers=Counter(flow.get("src","unknown") for flow in flows)
    return {"flow_count":len(flows),"protocols":dict(protocols),"top_talkers":talkers.most_common(5)}
