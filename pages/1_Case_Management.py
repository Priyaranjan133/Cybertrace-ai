import pandas as pd
import streamlit as st

from database import db_manager as db
from modules import ui, report_generator

ui.setup_page("Case Management", "🗂️")
st.title("🗂️ Case Management")
tab_cases, tab_evidence, tab_audit = st.tabs(["Cases", "Evidence", "Audit trail"])

with tab_cases:
    with st.form("new_case", clear_on_submit=True):
        st.subheader("Open a new case")
        title = st.text_input("Case title *")
        investigator = st.text_input("Lead investigator", value=ui.analyst())
        notes = st.text_area("Initial notes")
        if st.form_submit_button("Create case"):
            if not title.strip():
                st.error("A case title is required.")
            else:
                st.session_state["_pending_case"] = db.create_case(
                    title.strip(), investigator.strip() or ui.analyst(), notes, ui.analyst())
                st.rerun()

    cases = db.list_cases()
    if cases:
        st.dataframe(pd.DataFrame(cases)[["case_id", "title", "investigator", "status", "created_at"]], hide_index=True)
        case = ui.active_case()
        if case:
            st.subheader(f"Update {case['case_id']}")
            with st.form("update_case"):
                statuses = ["Open", "Under review", "Closed"]
                status = st.selectbox("Status", statuses,
                                      index=statuses.index(case["status"]) if case["status"] in statuses else 0)
                new_notes = st.text_area("Case notes", value=case.get("notes") or "")
                if st.form_submit_button("Save changes"):
                    db.update_case(case["case_id"], status, new_notes, ui.analyst())
                    st.success("Case updated.")
                    st.rerun()

with tab_evidence:
    case = ui.active_case()
    if not case:
        st.info("Create or select a case first.")
    else:
        cid = case["case_id"]
        st.session_state.setdefault("up_n", 0)
        files = st.file_uploader("Upload evidence (max 25 MB each)", accept_multiple_files=True,
                                 key=f"cm_up_{st.session_state['up_n']}")
        c1, c2 = st.columns(2)
        etype = c1.selectbox("Evidence type", ["Auto-detect"] + ui.EVIDENCE_TYPES)
        note = c2.text_input("Source / acquisition note (device, mailbox, ticket…)")
        if st.button("Acquire evidence", type="primary", disabled=not files):
            for f in files:
                kind = ui.guess_type(f.name) if etype == "Auto-detect" else etype
                db.add_evidence(cid, f.name, f.getvalue(), kind, ui.analyst(), note)
            st.session_state["up_n"] += 1
            st.rerun()

        evidence = db.list_evidence(cid)
        if evidence:
            df = pd.DataFrame(evidence)
            df["ID"] = "E" + df["id"].astype(str)
            df["Integrity"] = df["verified"].map({1: "✅ verified", 0: "❌ FAILED"}).fillna("unchecked")
            df["Reviewed"] = df["reviewed"].map({1: "yes", 0: "no"})
            st.dataframe(df[["ID", "filename", "evidence_type", "size", "sha256", "acquired_by", "acquired_at", "Integrity", "Reviewed"]],
                         hide_index=True)
            b1, b2 = st.columns(2)
            if b1.button("🔐 Re-verify all hashes"):
                report = db.verify_all(cid, ui.analyst())
                bad = [r for r in report if not r["ok"]]
                (st.error if bad else st.success)(
                    f"{len(bad)} item(s) FAILED integrity verification: " + ", ".join(f"E{r['id']} ({r['status']})" for r in bad)
                    if bad else f"All {len(report)} item(s) match their acquisition hash.")
            pending = [e for e in evidence if not e["reviewed"]]
            if pending:
                chosen = b2.multiselect("Mark as reviewed", [e["id"] for e in pending], format_func=lambda i: f"E{i}")
                if chosen and b2.button("Confirm review"):
                    db.mark_reviewed(chosen, ui.analyst())
                    st.rerun()
            st.download_button("⬇️ Evidence inventory (CSV)", report_generator.evidence_csv(evidence),
                               file_name=f"{cid}_evidence.csv", mime="text/csv")
        else:
            st.info("No evidence acquired for this case yet.")

with tab_audit:
    case = ui.active_case()
    ok, bad_id, n = db.verify_audit_chain()
    (st.success if ok else st.error)(f"Hash chain intact across {n} entries." if ok else f"Chain broken at entry #{bad_id}.")
    log = db.get_audit(case["case_id"] if case else None)
    if log:
        st.dataframe(pd.DataFrame(log)[["timestamp", "actor", "action", "detail", "entry_hash"]], hide_index=True)
    else:
        st.caption("No audit entries yet.")
