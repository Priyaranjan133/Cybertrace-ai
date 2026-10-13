"""Optional third-party reputation lookups (VirusTotal v3).

Results are *third-party opinions*, kept separate from evidence-derived facts.
Requires an API key supplied via Streamlit secrets / environment variable. Use only
indicators you are authorised to submit - lookups send the value to a third party.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

ENDPOINTS = {"ips": "ip_addresses", "domains": "domains", "hashes": "files"}


def vt_lookup(kind: str, value: str, api_key: str, timeout: int = 10) -> dict:
    if kind not in ENDPOINTS:
        return {"value": value, "status": "unsupported indicator type"}
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/{ENDPOINTS[kind]}/{value}", headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
            attrs = json.load(resp).get("data", {}).get("attributes", {})
    except urllib.error.HTTPError as exc:
        return {"value": value, "status": "not found" if exc.code == 404 else f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"value": value, "status": f"lookup failed: {exc}"}
    stats = attrs.get("last_analysis_stats", {})
    return {"value": value, "status": "ok", "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0),
            "reputation": attrs.get("reputation"), "source": "VirusTotal (third-party opinion)"}
