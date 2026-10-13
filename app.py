"""CyberTrace AI - digital forensics workbench (Streamlit entry point).

Run locally:  streamlit run app.py
"""
import pandas as pd
import streamlit as st

from database import db_manager as db
from modules import demo, ui
from modules.common import max_risk

ui.setup_page("Dashboard", "🛡️")

st.markdown("# 🛡️ CyberTrace AI")
st.markdown("<div class='ct-sub'>DIGITAL FORENSICS WORKBENCH</div>", unsafe_allow_html=True)
st.write("")

stats = db.stats()
m1, m2, m3, m4 = st.columns(4)
m1.metric("Active cases", stats["active_cases"])
m2.metric("Evidence items", stats["evidence"])
m3.metric("Pending review", stats["pending_review"])
m4.metric("Evidence verified", f"{stats['verified_pct']}%" if stats["verified_pct"] is not None else "-")

ok, bad_id, n_entries = db.verify_audit_chain()
if ok:
    st.caption(f"✅ Audit log hash-chain intact ({n_entries} entries)")
else:
    st.error(f"⚠️ Audit log tampering detected at entry #{bad_id}. Treat records after this point as untrusted.")

st.subheader("Investigation workflow")
steps = [("01", "Acquire evidence", "Upload and record source"), ("02", "Analyze artifacts", "Email, files and system logs"),
         ("03", "Correlate findings", "Build timelines and relationships"), ("04", "Export report", "Findings and supporting evidence")]
for col, (num, title, desc) in zip(st.columns(4), steps):
    col.markdown(f"<div class='ct-card'><div class='ct-step'>{num}</div><b>{title}</b><br><span>{desc}</span></div>",
                 unsafe_allow_html=True)

st.write("")
left, right = st.columns([2, 1])
with left:
    st.subheader("Cases")
    cases = db.list_cases()
    if cases:
        rows = []
        for c in cases:
            res = db.get_results(c["case_id"])
            rows.append({"Case": c["case_id"], "Title": c["title"], "Status": c["status"],
                         "Evidence": len(db.list_evidence(c["case_id"])),
                         "Highest risk": max_risk([r["risk"] for r in res]) if res else "-", "Opened": c["created_at"]})
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.info("No cases yet. Create one in **Case Management**, or load the demo case.")
with right:
    st.subheader("Try it")
    st.caption("Loads a synthetic case: a phishing email plus an SSH brute-force log that share an attacker IP.")
    if st.button("Load demo case", type="primary"):
        with st.spinner("Building demo case…"):
            st.session_state["_pending_case"] = demo.load_demo(ui.analyst())
        st.rerun()

st.subheader("Modules")
links = [("pages/1_Case_Management.py", "🗂️ Case management"), ("pages/2_Email_Forensics.py", "📧 Email forensics"),
         ("pages/3_File_Forensics.py", "📁 File forensics"), ("pages/4_Log_Investigation.py", "📜 Log investigation"),
         ("pages/5_Threat_Intelligence.py", "🕸️ Threat intelligence"), ("pages/6_Incident_Timeline.py", "⏱️ Incident timeline"),
         ("pages/7_Forensic_Reports.py", "📄 Forensic reports")]
for col, (path, label) in zip(st.columns(len(links)), links):
    col.page_link(path, label=label)

st.caption("Illustrative platform for authorised investigations. Automated findings are indicators, not legal conclusions.")
