"""Evidence-grounded investigation summaries.

Default: a deterministic, rule-based summary (no network, always reproducible).
Optional: if an Anthropic API key is configured, an LLM drafts the narrative from the
SAME structured findings, and is instructed to cite evidence IDs and not to invent facts.
Evidence contents are sent to a third party in that mode - only enable it where permitted.
"""
from __future__ import annotations

import os

from modules.common import max_risk, normalize_findings

SYSTEM_PROMPT = (
    "You are a digital-forensics reporting assistant. Write a concise investigation summary using ONLY the "
    "findings supplied. Cite evidence IDs like [E3] after each claim. Clearly separate (1) established facts "
    "from the evidence, (2) inferences, and (3) limitations. Never invent IPs, names, times or conclusions. "
    "Do not state legal conclusions."
)


def build_context(case: dict, evidence: list[dict], results: list[dict], correlations: list[dict]) -> str:
    lines = [f"CASE {case['case_id']}: {case['title']} (status {case['status']})"]
    lines.append("EVIDENCE:")
    for e in evidence:
        lines.append(f"- [E{e['id']}] {e['filename']} ({e['evidence_type']}), sha256={e['sha256']}")
    lines.append("FINDINGS:")
    for r in results:
        lines.append(f"[E{r['evidence_id']}] {r['module']} analysis - {r['summary']}")
        for f in normalize_findings(r)[:12]:
            lines.append(f"    * {f['severity']}: {f['finding']} {('(' + f['detail'] + ')') if f['detail'] else ''}")
    lines.append("CORRELATIONS:")
    lines += [f"- {c['explanation']}" for c in correlations] or ["- none"]
    return "\n".join(lines)


def rule_based_summary(case: dict, evidence: list[dict], results: list[dict], correlations: list[dict]) -> str:
    if not results:
        return f"No analysis has been run yet for case {case['case_id']}. Analyse the evidence items first."
    top = max_risk([r["risk"] for r in results])
    out = [f"Case {case['case_id']} ({case['title']}): {len(evidence)} evidence item(s) acquired and "
           f"{len(results)} analysis result(s) recorded. Highest observed risk: {top}.", "", "Key findings:"]
    for r in results:
        out.append(f"- [E{r['evidence_id']}] {r['summary']}")
        for f in [x for x in normalize_findings(r) if x["severity"] in ("Critical", "High")][:4]:
            out.append(f"    * {f['severity']}: {f['finding']}")
    out += ["", "Cross-evidence links:"]
    out += [f"- {c['explanation']}" for c in correlations] or ["- No indicator appears in more than one evidence item."]
    out += ["", "Limitations: automated, rule-based analysis; findings are indicators to be validated by an investigator. "
            "Hash verification and the audit log support integrity checks but do not by themselves establish legal admissibility."]
    return "\n".join(out)


def _api_key() -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    try:
        import streamlit as st
        return st.secrets.get("ANTHROPIC_API_KEY")
    except Exception:  # noqa: BLE001
        return None


def ai_available() -> bool:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return bool(_api_key())


def generate_summary(case, evidence, results, correlations, use_llm: bool = False) -> tuple[str, str]:
    """Return (text, mode) where mode is 'rule-based' or 'llm'."""
    fallback = rule_based_summary(case, evidence, results, correlations)
    if not (use_llm and ai_available()):
        return fallback, "rule-based"
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key())
        resp = client.messages.create(
            model=os.environ.get("CYBERTRACE_MODEL", "claude-sonnet-4-6"), max_tokens=1200, system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_context(case, evidence, results, correlations)}])
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
        return (text or fallback), ("llm" if text else "rule-based")
    except Exception as exc:  # noqa: BLE001
        return fallback + f"\n\n(LLM summary unavailable: {exc})", "rule-based"
