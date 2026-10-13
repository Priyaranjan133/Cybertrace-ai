from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from database import db_manager as db
from modules import pipeline, ui
from modules.common import normalize_findings

ui.setup_page("Log Investigation", "📜")
st.title("📜 Log Forensics & Incident Reconstruction")
st.caption("Supports Linux auth/syslog text and CSV exports (e.g. Windows Security events with TimeCreated, EventID, TargetUserName, IpAddress).")

case = ui.require_case()
cid = case["case_id"]
ev = ui.evidence_picker(["Log"], "Log", key="log")
if ev is None:
    st.info("Add a log file above to begin.")
    st.stop()

with st.expander("Detection parameters", expanded=False):
    p1, p2, p3 = st.columns(3)
    threshold = p1.number_input("Failed-login threshold", 2, 200, 5)
    window = p1.number_input("Window (minutes)", 1, 240, 10)
    off = p2.slider("Off-hours window (UTC hour)", 0, 24, (0, 6))
    succ_win = p2.number_input("Success-after-failure window (min)", 5, 720, 60)
    year = p3.number_input("Year for syslog timestamps", 2000, 2100, datetime.now(timezone.utc).year,
                           help="Syslog lines have no year. Timestamps are assumed to be UTC.")

results = db.get_results(cid, ev["id"], "log")
if st.button("🔍 Run / re-run analysis", type="primary") or not results:
    try:
        with st.spinner("Parsing and analysing…"):
            pipeline.run_log(cid, ev["id"], ui.analyst(), year=int(year), brute_threshold=int(threshold),
                             window_minutes=int(window), offhours=(off[0], off[1]), success_window_minutes=int(succ_win))
    except db.IntegrityError as exc:
        st.error(f"⛔ {exc}")
        st.stop()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Could not analyse this log: {exc}")
        st.stop()
    results = db.get_results(cid, ev["id"], "log")

res = results[0]
d = res["details"]
if d.get("note"):
    st.warning(d["note"])
    st.stop()

ui.risk_header(d["risk"], None, res["summary"])
s = d["stats"]
k1, k2, k3, k4 = st.columns(4)
k1.metric("Events parsed", f"{s['events']:,}")
k2.metric("Unique IPs", s["unique_ips"])
k3.metric("Unique users", s["unique_users"])
k4.metric("Failed logins", s["by_type"].get("login_failed", 0))
st.caption(f"Time range (UTC): {s['first']} → {s['last']}")

t_find, t_chart, t_ioc = st.tabs(["Findings", "Activity", "IPs"])
with t_find:
    ui.findings_table(normalize_findings(res))
with t_chart:
    hourly = pd.DataFrame(d["events_by_hour"])
    fig = px.bar(hourly, x="hour", y=["failed", "success", "other"], barmode="stack",
                 labels={"value": "events", "hour": "hour (UTC)", "variable": "type"},
                 color_discrete_map={"failed": "#dc2626", "success": "#16a34a", "other": "#64748b"})
    st.plotly_chart(fig)
    if d["failed_by_ip"]:
        top = pd.DataFrame(d["failed_by_ip"])
        st.plotly_chart(px.bar(top, x="ip", y="count", title="Top sources of failed logins", color_discrete_sequence=["#dc2626"]))
with t_ioc:
    ui.show_iocs(d["iocs"])
