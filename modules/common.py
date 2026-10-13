"""Shared helpers: risk labels, severity ordering and finding normalisation."""
from __future__ import annotations

RISK_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
RISK_COLORS = {
    "Info": "#64748b",
    "Low": "#2563eb",
    "Medium": "#d97706",
    "High": "#dc2626",
    "Critical": "#7f1d1d",
}


def risk_rank(label: str) -> int:
    return RISK_ORDER.index(label) if label in RISK_ORDER else 0


def risk_label(score: int) -> str:
    """Map a 0-100 score to a label. 'Critical' is reserved for log findings."""
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Info"


def max_risk(labels) -> str:
    labels = [l for l in labels if l in RISK_ORDER]
    return max(labels, key=risk_rank) if labels else "Info"


def badge_html(label: str) -> str:
    color = RISK_COLORS.get(label, "#64748b")
    return (
        f"<span style='background:{color};color:white;padding:2px 10px;"
        f"border-radius:999px;font-size:0.8rem;font-weight:600'>{label}</span>"
    )


def normalize_findings(result: dict) -> list[dict]:
    """Return a flat list of {severity, finding, detail} for any analysis result."""
    details = result.get("details") or {}
    out: list[dict] = []
    if result.get("module") == "log":
        for f in details.get("findings", []):
            out.append(
                {
                    "severity": f.get("severity", "Info"),
                    "finding": f.get("description", ""),
                    "detail": f"{f.get('type', '')} | events={f.get('count', '')}",
                }
            )
    else:
        for i in details.get("indicators", []):
            out.append(
                {
                    "severity": i.get("severity", "Info"),
                    "finding": i.get("finding", ""),
                    "detail": i.get("evidence", ""),
                }
            )
    out.sort(key=lambda x: -risk_rank(x["severity"]))
    return out
