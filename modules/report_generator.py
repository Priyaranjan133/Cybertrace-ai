"""PDF and CSV exports of an investigation."""
from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from database import db_manager as db
from modules.common import normalize_findings, risk_rank


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")).replace("\n", "<br/>"), style)


def _table(rows, widths, header_bg="#0f172a"):
    t = Table(rows, colWidths=[w * mm for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def build_pdf(case: dict, evidence: list[dict], results: list[dict], correlations: list[dict],
              audit: list[dict], summary: str = "") -> bytes:
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9)
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=6.5, leading=8)
    head = ParagraphStyle("head", parent=small, textColor=colors.white, fontName="Helvetica-Bold")
    h1, h2 = ss["Heading1"], ss["Heading2"]

    story = [Paragraph("Digital Forensic Investigation Report", ss["Title"]),
             _p(f"{case['case_id']} - {case['title']}", ss["Heading3"]), Spacer(1, 4 * mm)]

    story.append(Paragraph("1. Case information", h1))
    info = [["Case ID", case["case_id"]], ["Title", case["title"]], ["Lead investigator", case.get("investigator", "")],
            ["Status", case["status"]], ["Opened (UTC)", case["created_at"]], ["Report generated (UTC)", db.now_iso()],
            ["Notes", case.get("notes") or "-"]]
    story.append(_table([[_p(a, small), _p(b, small)] for a, b in info], [40, 130], header_bg="#ffffff"))

    story += [Paragraph("2. Executive summary", h1), _p(summary or "No summary provided.", body)]

    story.append(Paragraph("3. Evidence inventory", h1))
    rows = [[_p(c, head) for c in ("ID", "File", "Type", "SHA-256", "Acquired (UTC) / by", "Integrity")]]
    for e in evidence:
        status = {1: "Verified", 0: "FAILED"}.get(e.get("verified"), "Unchecked")
        rows.append([_p(f"E{e['id']}", small), _p(e["filename"], small), _p(e["evidence_type"], small),
                     _p(e["sha256"], mono), _p(f"{e['acquired_at']}\n{e['acquired_by']}", small), _p(status, small)])
    story.append(_table(rows, [9, 34, 14, 62, 33, 18]))

    story.append(Paragraph("4. Methods", h1))
    story.append(_p("Evidence was stored read-only and identified by SHA-256 at acquisition; hashes are re-verified before each analysis. "
                    "Files were analysed statically and never executed. Email analysis covers header authentication results, routing, "
                    "link and attachment inspection. Log analysis normalises events to UTC and applies threshold-based detections. "
                    "Indicators were extracted and correlated across evidence items. All analyst actions are recorded in a hash-chained audit log.", body))

    story.append(Paragraph("5. Findings", h1))
    ev_by_id = {e["id"]: e for e in evidence}
    for r in sorted(results, key=lambda r: -risk_rank(r["risk"])):
        e = ev_by_id.get(r["evidence_id"], {})
        story += [Paragraph(escape(f"E{r['evidence_id']} - {e.get('filename', '?')} ({r['module']}) - risk: {r['risk']}"), h2),
                  _p(r["summary"], body)]
        fnd = normalize_findings(r)[:20]
        if fnd:
            rows = [[_p(c, head) for c in ("Severity", "Finding", "Detail")]]
            rows += [[_p(f["severity"], small), _p(f["finding"], small), _p(f["detail"], small)] for f in fnd]
            story.append(_table(rows, [18, 90, 62]))
        story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("6. Cross-evidence correlations", h1))
    if correlations:
        rows = [[_p(c, head) for c in ("Type", "Indicator", "Found in")]]
        rows += [[_p(c["type"], small), _p(c["value"], small), _p(", ".join(c["evidence"]), small)] for c in correlations[:50]]
        story.append(_table(rows, [24, 70, 76]))
    else:
        story.append(_p("No indicator appears in more than one evidence item.", body))

    story += [PageBreak(), Paragraph("7. Audit trail (most recent entries)", h1)]
    rows = [[_p(c, head) for c in ("Time (UTC)", "Actor", "Action", "Detail")]]
    rows += [[_p(a["timestamp"], small), _p(a["actor"], small), _p(a["action"], small), _p((a["detail"] or "")[:140], small)]
             for a in audit[:60]]
    story.append(_table(rows, [30, 22, 30, 88]))

    story.append(Paragraph("8. Limitations", h1))
    story.append(_p("Automated findings are indicators, not conclusions, and must be validated by a qualified investigator. "
                    "Third-party reputation data (if used) is opinion, not evidence. Timestamps from syslog assume UTC and the stated year. "
                    "Hash verification and an audit log support integrity checks but do not alone establish legal admissibility.", body))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(20 * mm, 10 * mm, f"CyberTrace AI - {case['case_id']} - CONFIDENTIAL")
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buf = BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
                      title=f"Forensic report {case['case_id']}").build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def evidence_csv(evidence: list[dict]) -> bytes:
    cols = ["id", "case_id", "filename", "evidence_type", "size", "sha256", "md5", "sha1", "acquired_by", "acquired_at", "verified", "source_note"]
    return pd.DataFrame(evidence, columns=cols).to_csv(index=False).encode()


def findings_csv(results: list[dict], evidence: list[dict]) -> bytes:
    names = {e["id"]: e["filename"] for e in evidence}
    rows = [{"evidence_id": r["evidence_id"], "file": names.get(r["evidence_id"], ""), "module": r["module"],
             **f} for r in results for f in normalize_findings(r)]
    return pd.DataFrame(rows, columns=["evidence_id", "file", "module", "severity", "finding", "detail"]).to_csv(index=False).encode()
