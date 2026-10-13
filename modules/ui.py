"""Shared Streamlit UI helpers: page setup, access gate, sidebar, pickers and tables."""
from __future__ import annotations

import hmac
import os

import pandas as pd
import streamlit as st

from database import db_manager as db
from modules.common import RISK_COLORS, badge_html, risk_rank

EVIDENCE_TYPES = ["Email", "File", "Log", "Other"]

CSS = """
<style>
.ct-card{border:1px solid rgba(128,128,128,.25);border-radius:12px;padding:14px 16px;height:100%}
.ct-step{font-size:.8rem;letter-spacing:.12em;color:#38bdf8;font-weight:700}
.ct-card span{opacity:.75;font-size:.9rem}
.ct-sub{letter-spacing:.2em;font-size:.75rem;opacity:.6}
</style>
"""


def secret(name: str):
    """Read a secret from the environment or Streamlit secrets; None if unset."""
    value = os.environ.get(name)
    if value:
        return value
    try:
        return st.secrets.get(name)
    except Exception:  # noqa: BLE001 - no secrets file configured
        return None


def _auth_gate() -> None:
    password = secret("APP_PASSWORD")
    if not password or st.session_state.get("_authed"):
        return
    st.title("🔒 CyberTrace AI")
    entered = st.text_input("Access password", type="password")
    if entered:
        if hmac.compare_digest(entered.encode(), str(password).encode()):
            st.session_state["_authed"] = True
            st.rerun()
        st.error("Incorrect password.")
    st.stop()


def analyst() -> str:
    return (st.session_state.get("analyst") or "analyst").strip() or "analyst"


def active_case() -> dict | None:
    return db.get_case(st.session_state.get("active_case"))


def require_case() -> dict:
    case = active_case()
    if case is None:
        st.info("Create or select a case first (sidebar, or the **Case Management** page).")
        st.stop()
    return case


def _sidebar() -> None:
    with st.sidebar:
        st.markdown("### 🛡️ CyberTrace AI")
        st.text_input("Analyst name", value="analyst", key="analyst", help="Recorded in the audit log.")
        cases = db.list_cases()
        if "_pending_case" in st.session_state:  # set by pages that just created a case
            st.session_state["active_case"] = st.session_state.pop("_pending_case")
        if cases:
            labels = {c["case_id"]: f"{c['case_id']} - {c['title']}" for c in cases}
            st.selectbox("Active case", list(labels), format_func=labels.get, key="active_case")
        else:
            st.caption("No cases yet.")
        st.divider()
        st.caption("Submitted files are stored read-only and analysed statically. They are never executed.")


def setup_page(title: str, icon: str = "🛡️") -> None:
    st.set_page_config(page_title=f"{title} - CyberTrace AI", page_icon=icon, layout="wide")
    db.init_db()
    _auth_gate()
    st.markdown(CSS, unsafe_allow_html=True)
    _sidebar()


def guess_type(filename: str) -> str:
    f = filename.lower()
    if f.endswith((".eml", ".msg")):
        return "Email"
    if f.endswith((".log", ".csv", ".evtx", ".txt")) and not f.endswith("readme.txt"):
        return "Log" if f.endswith((".log", ".csv")) else "File"
    return "File"


def evidence_picker(kinds: list[str] | None, upload_type: str, key: str) -> dict | None:
    """Select an evidence item of the given kinds, with inline upload."""
    case = require_case()
    items = [e for e in db.list_evidence(case["case_id"]) if kinds is None or e["evidence_type"] in kinds]
    counter = f"{key}_n"
    st.session_state.setdefault(counter, 0)
    with st.expander("➕ Add new evidence to this case", expanded=not items):
        up = st.file_uploader("Select a file", key=f"{key}_up_{st.session_state[counter]}")
        note = st.text_input("Source / acquisition note", key=f"{key}_note")
        if st.button("Acquire evidence", key=f"{key}_acq", disabled=up is None):
            new_id = db.add_evidence(case["case_id"], up.name, up.getvalue(), upload_type, analyst(), note)
            st.session_state[f"{key}_sel"] = new_id
            st.session_state[counter] += 1
            st.rerun()
    if not items:
        return None
    labels = {e["id"]: f"E{e['id']} - {e['filename']} ({e['sha256'][:10]}…)" for e in items}
    chosen = st.selectbox("Evidence item", list(labels), format_func=labels.get, key=f"{key}_sel")
    return next(e for e in items if e["id"] == chosen)


def findings_table(findings: list[dict]) -> None:
    if not findings:
        st.success("No indicators raised.")
        return
    df = pd.DataFrame(findings).rename(columns=str.title)
    st.dataframe(df, hide_index=True)


def risk_header(label: str, score: int | None = None, summary: str = "") -> None:
    cols = st.columns([1, 1, 4])
    cols[0].markdown("**Risk**<br>" + badge_html(label), unsafe_allow_html=True)
    if score is not None:
        cols[1].metric("Score", f"{score}/100")
    if summary:
        cols[2].caption(summary)


def show_iocs(iocs: dict) -> None:
    rows = [{"Type": k.rstrip("s").title(), "Indicator": v} for k, vals in iocs.items() for v in vals]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.caption("No indicators of compromise extracted.")


def sort_by_risk(rows: list[dict], field: str = "risk") -> list[dict]:
    return sorted(rows, key=lambda r: -risk_rank(r.get(field, "Info")))


__all__ = ["RISK_COLORS"]
