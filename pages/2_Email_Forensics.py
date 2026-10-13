import pandas as pd
import streamlit as st

from database import db_manager as db
from modules import pipeline, ui
from modules.common import normalize_findings

ui.setup_page("Email Forensics", "📧")
st.title("📧 Email Forensics & Phishing Investigation")
st.caption("Parses .eml files as data: HTML is never rendered, links are never visited and attachments are never opened.")

case = ui.require_case()
cid = case["case_id"]
ev = ui.evidence_picker(["Email"], "Email", key="email")
if ev is None:
    st.info("Add an .eml file above to begin.")
    st.stop()

results = db.get_results(cid, ev["id"], "email")
if st.button("🔍 Run / re-run analysis", type="primary") or not results:
    try:
        with st.spinner("Analysing…"):
            pipeline.run_email(cid, ev["id"], ui.analyst())
    except db.IntegrityError as exc:
        st.error(f"⛔ {exc}")
        st.stop()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Could not analyse this file: {exc}")
        st.stop()
    results = db.get_results(cid, ev["id"], "email")

res = results[0]
d = res["details"]
ui.risk_header(d["risk"], d["score"], res["summary"])

auth = d["authentication"]
icons = {"pass": "✅", "fail": "❌", "softfail": "⚠️"}
a1, a2, a3, a4 = st.columns(4)
for col, key in zip((a1, a2, a3), ("spf", "dkim", "dmarc")):
    col.metric(key.upper(), f"{icons.get(auth[key], '❔')} {auth[key] or 'not present'}")
a4.metric("Origin IP (first public hop)", d.get("origin_ip") or "-")

t_find, t_head, t_route, t_links, t_att, t_ioc, t_body = st.tabs(
    ["Findings", "Headers", "Routing", "Links", "Attachments", "IOCs", "Body preview"])
with t_find:
    ui.findings_table(normalize_findings(res))
with t_head:
    st.dataframe(pd.DataFrame(d["headers"].items(), columns=["Header", "Value"]), hide_index=True)
with t_route:
    st.caption("Oldest hop first. Only the hop added by your own mail server is fully trustworthy.")
    hops = [{"From": h["from"], "By": h["by"], "IPs": ", ".join(h["ips"]), "Timestamp (UTC)": h["timestamp_utc"]} for h in d["routing"]]
    st.dataframe(pd.DataFrame(hops), hide_index=True) if hops else st.caption("No Received headers.")
with t_links:
    st.warning("Do not open these links outside an isolated environment.")
    links = [{"URL": u["url"], "Anchor text": u["anchor_text"], "Flags": "; ".join(u["flags"])} for u in d["urls"]]
    st.dataframe(pd.DataFrame(links), hide_index=True) if links else st.caption("No links found.")
with t_att:
    if d["attachments"]:
        st.dataframe(pd.DataFrame([{k: a[k] for k in ("filename", "size", "detected_type", "risk", "score", "sha256")}
                                   for a in d["attachments"]]), hide_index=True)
        for a in d["attachments"]:
            with st.expander(f"Indicators for {a['filename']}"):
                ui.findings_table([{"severity": i["severity"], "finding": i["finding"], "evidence": i["evidence"]} for i in a["indicators"]])
    else:
        st.caption("No attachments.")
with t_ioc:
    ui.show_iocs(d["iocs"])
with t_body:
    st.code(d["body_preview"] or "(empty)", language=None)
