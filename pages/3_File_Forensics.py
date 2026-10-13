import pandas as pd
import streamlit as st

from database import db_manager as db
from modules import pipeline, ui
from modules.common import normalize_findings

ui.setup_page("File Forensics", "📁")
st.title("📁 File Forensics & Evidence Integrity")
st.caption("Static analysis only - files are hashed and inspected as bytes, never executed or extracted to disk.")

case = ui.require_case()
cid = case["case_id"]
ev = ui.evidence_picker(None, "File", key="file")
if ev is None:
    st.info("Add a file above to begin.")
    st.stop()

results = db.get_results(cid, ev["id"], "file")
if st.button("🔍 Run / re-run analysis", type="primary") or not results:
    try:
        with st.spinner("Analysing…"):
            pipeline.run_file(cid, ev["id"], ui.analyst())
    except db.IntegrityError as exc:
        st.error(f"⛔ {exc}")
        st.stop()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Could not analyse this file: {exc}")
        st.stop()
    results = db.get_results(cid, ev["id"], "file")

res = results[0]
d = res["details"]
ui.risk_header(d["risk"], d["score"], res["summary"])

c1, c2, c3, c4 = st.columns(4)
c1.metric("Size (bytes)", f"{d['size']:,}")
c2.metric("Claimed extension", f".{d['claimed_extension']}" if d["claimed_extension"] else "none")
c3.metric("Detected type", d["detected_type"])
c4.metric("Entropy", f"{d['entropy']} / 8")
if not d["extension_matches"]:
    st.warning("The file extension does not match the file's real content signature.")

t_find, t_hash, t_meta, t_arch, t_ioc = st.tabs(["Findings", "Hashes", "Metadata", "Archive contents", "IOCs"])
with t_find:
    ui.findings_table(normalize_findings(res))
with t_hash:
    for algo in ("sha256", "sha1", "md5"):
        st.markdown(f"**{algo.upper()}**")
        st.code(d["hashes"][algo], language=None)
    st.caption("Recomputed from stored bytes before every analysis; a mismatch blocks the analysis.")
with t_meta:
    meta = d.get("metadata") or {}
    st.dataframe(pd.DataFrame(meta.items(), columns=["Field", "Value"]), hide_index=True) if meta else st.caption("No embedded metadata found.")
with t_arch:
    arch = d.get("archive")
    if arch and arch.get("entries"):
        st.caption(f"{arch['total_entries']} entries, compression ratio {arch.get('compression_ratio')}:1 (listing capped at 200)")
        st.dataframe(pd.DataFrame(arch["entries"]), hide_index=True)
    else:
        st.caption("Not an archive.")
with t_ioc:
    ui.show_iocs(d["iocs"])
