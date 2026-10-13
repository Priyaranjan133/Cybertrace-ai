import streamlit as st

from database import db_manager as db
from modules import ai_assistant as ai
from modules import correlation_engine as ce
from modules import report_generator as rg
from modules import ui

ui.setup_page("Forensic Reports", "📄")
st.title("📄 Forensic Reports")

case = ui.require_case()
cid = case["case_id"]
evidence = db.list_evidence(cid)
results = db.get_results(cid)
correlations = ce.correlate(results, {e["id"]: e for e in evidence})

st.subheader("Executive summary")
use_llm = st.checkbox("Draft with an LLM (Anthropic API)", value=False, disabled=not ai.ai_available(),
                      help="Requires the `anthropic` package and ANTHROPIC_API_KEY. Sends findings to a third party.")
if not ai.ai_available():
    st.caption("Using the built-in rule-based summary. Set ANTHROPIC_API_KEY to enable optional LLM drafting.")
sum_key = f"summary_{cid}"
if st.button("Generate summary from findings"):
    text, mode = ai.generate_summary(case, evidence, results, correlations, use_llm=use_llm)
    st.session_state[sum_key] = text
    st.caption(f"Generated with: {mode}")
summary = st.text_area("Summary (editable before export)", height=300, key=sum_key,
                       value=ai.rule_based_summary(case, evidence, results, correlations))

st.subheader("Export")
if st.button("📄 Build PDF report", type="primary"):
    with st.spinner("Re-verifying evidence and building report…"):
        db.verify_all(cid, ui.analyst())
        evidence = db.list_evidence(cid)
        pdf = rg.build_pdf(case, evidence, results, correlations, db.get_audit(cid), summary)
        db.log_action(cid, ui.analyst(), "report_generated", f"{len(pdf):,} bytes")
    st.session_state[f"pdf_{cid}"] = pdf
if f"pdf_{cid}" in st.session_state:
    st.download_button("⬇️ Download PDF", st.session_state[f"pdf_{cid}"], file_name=f"{cid}_report.pdf", mime="application/pdf")

d1, d2 = st.columns(2)
d1.download_button("⬇️ Evidence inventory (CSV)", rg.evidence_csv(evidence), file_name=f"{cid}_evidence.csv", mime="text/csv")
d2.download_button("⬇️ Findings (CSV)", rg.findings_csv(results, evidence), file_name=f"{cid}_findings.csv", mime="text/csv")
