import pandas as pd
import plotly.express as px
import streamlit as st

from database import db_manager as db
from modules import ui
from modules.common import RISK_COLORS, RISK_ORDER, risk_rank

ui.setup_page("Incident Timeline", "⏱️")
st.title("⏱️ Incident Timeline Reconstruction")
st.caption("Events from every analysis are normalised to UTC, merged and sorted. Choose a display time zone below.")

case = ui.require_case()
cid = case["case_id"]
results = db.get_results(cid)
events = [dict(e) for r in results for e in r["details"].get("timeline", [])]
for e in db.list_evidence(cid):
    events.append({"timestamp": e["acquired_at"], "source": "case", "event": "Evidence acquired",
                   "detail": f"E{e['id']} {e['filename']}", "severity": "Info"})
if len(events) <= len(db.list_evidence(cid)):
    st.info("No analysed events yet. Run an email or log analysis first.")
    st.stop()

tz = st.selectbox("Display time zone", ["UTC", "Asia/Kolkata", "Europe/London", "America/New_York",
                                         "America/Los_Angeles", "Asia/Tokyo", "Australia/Sydney"])
df = pd.DataFrame(events)
df["time"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
df = df.dropna(subset=["time"]).sort_values("time")
df["time"] = df["time"].dt.tz_convert(tz)

c1, c2 = st.columns(2)
sources = c1.multiselect("Sources", sorted(df["source"].unique()), default=sorted(df["source"].unique()))
min_sev = c2.select_slider("Minimum severity", RISK_ORDER, value="Info")
view = df[df["source"].isin(sources) & (df["severity"].map(risk_rank) >= risk_rank(min_sev))]

st.subheader("Suspicious sequence")
sus = view[view["severity"].map(risk_rank) >= risk_rank("High")]
if sus.empty:
    st.caption("No High/Critical events in the current selection.")
else:
    st.dataframe(sus[["time", "severity", "source", "event", "detail"]].rename(columns=str.title), hide_index=True)

st.subheader("All events")
if view.empty:
    st.caption("Nothing matches the filters.")
else:
    fig = px.scatter(view, x="time", y="source", color="severity", hover_data=["event", "detail"],
                     color_discrete_map=RISK_COLORS, category_orders={"severity": RISK_ORDER})
    fig.update_traces(marker=dict(size=11))
    fig.update_layout(height=360, xaxis_title=f"Time ({tz})")
    st.plotly_chart(fig)
    st.dataframe(view[["time", "severity", "source", "event", "detail"]].rename(columns=str.title), hide_index=True)
st.caption("Syslog timestamps carry no time zone or year; they are treated as UTC using the year you set on the Log page.")
