"""Cross-evidence correlation: find indicators that appear in more than one evidence item."""
from __future__ import annotations

import math
from collections import defaultdict

from modules.ioc_extractor import IOC_KINDS

KIND_LABEL = {"ips": "IP address", "domains": "Domain", "urls": "URL", "hashes": "File hash", "emails": "Email address"}


def collect_iocs(results: list[dict]) -> dict:
    """{(kind, value): set(evidence_id)} across all analysis results."""
    index: dict = defaultdict(set)
    for r in results:
        iocs = (r.get("details") or {}).get("iocs", {})
        for kind in IOC_KINDS:
            for value in iocs.get(kind, []):
                index[(kind, value)].add(r["evidence_id"])
    return index


def correlate(results: list[dict], evidence_by_id: dict) -> list[dict]:
    out = []
    for (kind, value), ev_ids in collect_iocs(results).items():
        if len(ev_ids) < 2:
            continue
        names = [f"E{i} ({evidence_by_id[i]['filename']})" for i in sorted(ev_ids) if i in evidence_by_id]
        out.append({
            "type": KIND_LABEL[kind], "value": value, "evidence_ids": sorted(ev_ids),
            "evidence": names,
            "explanation": f"{KIND_LABEL[kind]} {value} appears in {len(ev_ids)} evidence items: {', '.join(names)}",
        })
    out.sort(key=lambda c: (-len(c["evidence_ids"]), c["type"], c["value"]))
    return out


def build_graph(results: list[dict], evidence_by_id: dict, only_shared: bool = False, max_iocs: int = 60) -> dict:
    """Bipartite evidence<->IOC graph with a deterministic circular layout (no extra deps)."""
    index = collect_iocs(results)
    items = [(k, v) for (k, v), ids in index.items() if (len(ids) > 1 or not only_shared)]
    items.sort(key=lambda kv: -len(index[kv]))
    items = items[:max_iocs]
    ev_ids = sorted({i for kv in items for i in index[kv]})

    nodes, edges = {}, []
    for n, i in enumerate(ev_ids):
        a = 2 * math.pi * n / max(len(ev_ids), 1)
        nodes[f"E{i}"] = {"label": f"E{i}: {evidence_by_id[i]['filename']}" if i in evidence_by_id else f"E{i}",
                          "kind": "evidence", "x": 0.45 * math.cos(a), "y": 0.45 * math.sin(a)}
    for n, (kind, value) in enumerate(items):
        a = 2 * math.pi * n / max(len(items), 1)
        nodes[f"{kind}:{value}"] = {"label": value, "kind": KIND_LABEL[kind], "x": math.cos(a), "y": math.sin(a),
                                    "shared": len(index[(kind, value)]) > 1}
        for i in index[(kind, value)]:
            edges.append((f"E{i}", f"{kind}:{value}"))
    return {"nodes": nodes, "edges": edges}
