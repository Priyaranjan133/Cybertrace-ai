"""One-click demo case built from the harmless files in sample_data/."""
from __future__ import annotations

from pathlib import Path

from database import db_manager as db
from modules import pipeline

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
DEMO_TITLE = "DEMO - Phishing email followed by SSH compromise"


def load_demo(actor: str = "analyst") -> str:
    for c in db.list_cases():
        if c["title"] == DEMO_TITLE:
            return c["case_id"]
    cid = db.create_case(DEMO_TITLE, actor, "Synthetic demo data (RFC 5737 IPs, .example domains). Not real evidence.", actor)
    eml = db.add_evidence(cid, "phishing_sample.eml", (SAMPLE_DIR / "phishing_sample.eml").read_bytes(), "Email", actor, "Demo mailbox export")
    log = db.add_evidence(cid, "auth_sample.log", (SAMPLE_DIR / "auth_sample.log").read_bytes(), "Log", actor, "Demo web01 /var/log/auth.log")
    pipeline.run_email(cid, eml, actor)
    pipeline.run_log(cid, log, actor, year=2026)
    return cid
