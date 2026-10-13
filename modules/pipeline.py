"""Glue between stored evidence, the analyzers and the database."""
from __future__ import annotations

from database import db_manager as db
from modules import email_analyzer, file_analyzer, log_analyzer


def run_email(case_id: str, evidence_id: int, actor: str) -> dict:
    data = db.read_evidence_bytes(evidence_id)
    d = email_analyzer.analyze_eml(data)
    summary = (f"Phishing risk {d['risk']} (score {d['score']}/100) - {len(d['indicators'])} indicator(s), "
               f"{len(d['urls'])} URL(s), {len(d['attachments'])} attachment(s)")
    db.save_result(case_id, evidence_id, "email", d["risk"], summary, d, actor)
    return d


def run_file(case_id: str, evidence_id: int, actor: str) -> dict:
    ev = db.get_evidence(evidence_id)
    data = db.read_evidence_bytes(evidence_id)
    d = file_analyzer.analyze_file(ev["filename"], data)
    summary = f"File risk {d['risk']} (score {d['score']}/100) - detected as {d['detected_type']}"
    db.save_result(case_id, evidence_id, "file", d["risk"], summary, d, actor)
    return d


def run_log(case_id: str, evidence_id: int, actor: str, year: int | None = None, **params) -> dict:
    ev = db.get_evidence(evidence_id)
    data = db.read_evidence_bytes(evidence_id)
    d = log_analyzer.analyze_log(data, ev["filename"], year, **params)
    summary = f"{d['stats'].get('events', 0)} events, {len(d['findings'])} finding(s); highest severity {d['risk']}"
    db.save_result(case_id, evidence_id, "log", d["risk"], summary, d, actor)
    return d
