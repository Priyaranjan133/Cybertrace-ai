import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from database import db_manager as db
from modules import correlation_engine as ce
from modules import threat_intel, ui

ui.setup_page("Threat Intelligence", "🕸️")
st.title("🕸️ Threat Intelligence & IOC Analysis")

case = ui.require_case()
cid = case["case_id"]
results = db.get_results(cid)
evidence = db.list_evidence(cid)
ev_by_id = {e["id"]: e for e in evidence}
if not results:
    st.info("Run at least one analysis (email, file or log) to extract indicators.")
    st.stop()

index = ce.collect_iocs(results)
correlations = ce.correlate(results, ev_by_id)
tab_facts, tab_graph, tab_rep = st.tabs(["Evidence-derived indicators", "Relationship graph", "Third-party reputation"])

with tab_facts:
    st.caption("Everything here was extracted from your evidence. Reputation opinions are kept in a separate tab.")
    st.subheader("Cross-evidence correlations")
    if correlations:
        st.dataframe(pd.DataFrame([{"Type": c["type"], "Indicator": c["value"], "Found in": ", ".join(c["evidence"])}
                                   for c in correlations]), hide_index=True)
    else:
        st.info("No indicator appears in more than one evidence item yet.")
    st.subheader("All indicators")
    rows = [{"Type": ce.KIND_LABEL[k], "Indicator": v, "Evidence items": len(ids),
             "Seen in": ", ".join(f"E{i}" for i in sorted(ids))} for (k, v), ids in index.items()]
    df = pd.DataFrame(rows)
    kinds = st.multiselect("Filter by type", sorted(df["Type"].unique()), default=sorted(df["Type"].unique())) if not df.empty else []
    if not df.empty:
        st.dataframe(df[df["Type"].isin(kinds)].sort_values(["Evidence items", "Type"], ascending=[False, True]), hide_index=True)

with tab_graph:
    only_shared = st.checkbox("Show only indicators shared by 2+ evidence items", value=len(correlations) > 0)
    g = ce.build_graph(results, ev_by_id, only_shared=only_shared)
    if not g["nodes"]:
        st.info("Nothing to draw yet.")
    else:
        ex, ey = [], []
        for a, b in g["edges"]:
            ex += [g["nodes"][a]["x"], g["nodes"][b]["x"], None]
            ey += [g["nodes"][a]["y"], g["nodes"][b]["y"], None]
        fig = go.Figure(go.Scatter(x=ex, y=ey, mode="lines", line=dict(width=1, color="#94a3b8"), hoverinfo="skip", showlegend=False))
        palette = {"evidence": "#38bdf8", "IP address": "#dc2626", "Domain": "#d97706", "URL": "#a855f7",
                   "File hash": "#16a34a", "Email address": "#64748b"}
        for kind, color in palette.items():
            pts = [n for n in g["nodes"].values() if n["kind"] == kind]
            if pts:
                fig.add_trace(go.Scatter(
                    x=[p["x"] for p in pts], y=[p["y"] for p in pts], mode="markers", name=kind, text=[p["label"] for p in pts],
                    hoverinfo="text", marker=dict(size=[18 if p["kind"] == "evidence" else (16 if p.get("shared") else 9) for p in pts],
                                                  color=color, line=dict(width=1, color="white"))))
        fig.update_layout(height=560, xaxis=dict(visible=False), yaxis=dict(visible=False, scaleanchor="x"),
                          margin=dict(l=0, r=0, t=10, b=0), legend=dict(orientation="h"))
        st.plotly_chart(fig)
        st.caption("Blue nodes are evidence items; other nodes are indicators. Larger indicator nodes appear in more than one item.")

with tab_rep:
    st.warning("Lookups send the indicator to a third party (VirusTotal). Only submit values you are authorised to share. "
               "Results are opinions from that service, not forensic facts.")
    key = ui.secret("VT_API_KEY")
    if not key:
        st.info("Add `VT_API_KEY` to Streamlit secrets (or the environment) to enable lookups.")
    else:
        candidates = [(k, v) for (k, v) in index if k in ("ips", "domains", "hashes")]
        picked = st.multiselect("Indicators (max 4 per run - free API quota is limited)", candidates,
                                format_func=lambda kv: f"{ce.KIND_LABEL[kv[0]]}: {kv[1]}", max_selections=4)
        if st.button("Look up", disabled=not picked):
            out = [threat_intel.vt_lookup(k, v, key) for k, v in picked]
            st.dataframe(pd.DataFrame(out), hide_index=True)
            db.log_action(cid, ui.analyst(), "threat_intel_lookup", f"{len(picked)} indicator(s) sent to VirusTotal")
