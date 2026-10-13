"""Email (.eml) forensics and explainable phishing assessment.

The message is parsed as data only: HTML is never rendered, attachments are never
opened or executed.
"""
from __future__ import annotations

import re
from datetime import timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlparse

from modules.common import risk_label
from modules.file_analyzer import analyze_file
from modules.ioc_extractor import IPV4_RE, URL_RE, extract_iocs, is_ip, is_public_ip, merge_iocs

BRANDS = {"paypal", "microsoft", "amazon", "apple", "google", "netflix", "dhl", "fedex", "docusign",
          "linkedin", "facebook", "instagram", "outlook", "office365", "bank"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "buff.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "tk", "ml", "ga", "cf", "work", "zip", "mov", "support", "country"}
URGENCY = ["urgent", "immediately", "verify your account", "account suspended", "has been suspended",
           "password expires", "confirm your", "within 24 hours", "unusual activity", "invoice attached",
           "wire transfer", "gift card", "act now", "final notice", "click here"]


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _addr_domain(value: str) -> str:
    _, addr = parseaddr(value or "")
    return addr.rsplit("@", 1)[1].lower().strip("> ") if "@" in addr else ""


def _base_domain(host: str) -> str:
    parts = [p for p in (host or "").lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


def _host(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def _to_utc_iso(dt) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_date(value: str):
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None


def _auth_results(msg) -> dict:
    out = {"spf": None, "dkim": None, "dmarc": None}
    for header in msg.get_all("Authentication-Results", []):
        for key in out:
            m = re.search(rf"\b{key}=(\w+)", str(header), re.I)
            if m and out[key] is None:
                out[key] = m.group(1).lower()
    received_spf = msg.get("Received-SPF")
    if received_spf and out["spf"] is None:
        m = re.match(r"\s*(\w+)", str(received_spf))
        if m:
            out["spf"] = m.group(1).lower()
    return out


def _url_flags(url: str) -> list[str]:
    flags = []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return ["Malformed URL"]
    if is_ip(host):
        flags.append("IP-address host")
    if host in SHORTENERS:
        flags.append("URL shortener")
    if "xn--" in host:
        flags.append("Punycode (possible homograph)")
    if "@" in p.netloc:
        flags.append("Credentials/@ in URL")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Frequently abused TLD (.{tld})")
    if p.scheme == "http":
        flags.append("Unencrypted HTTP")
    return flags


def analyze_eml(data: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    score = 0
    indicators: list[dict] = []

    def flag(sev: str, pts: int, finding: str, evidence: str = "") -> None:
        nonlocal score
        score += pts
        indicators.append({"severity": sev, "finding": finding, "evidence": evidence})

    get = lambda name: str(msg.get(name, "") or "")  # noqa: E731
    from_h, reply_h, rpath_h = get("From"), get("Reply-To"), get("Return-Path")
    display_name, from_addr = parseaddr(from_h)
    from_dom, reply_dom, rpath_dom = _addr_domain(from_h), _addr_domain(reply_h), _addr_domain(rpath_h)

    headers = {
        "From": from_h, "To": get("To"), "Cc": get("Cc"), "Subject": get("Subject"), "Date": get("Date"),
        "Message-ID": get("Message-ID"), "Reply-To": reply_h, "Return-Path": rpath_h,
        "X-Mailer": get("X-Mailer"), "User-Agent": get("User-Agent"),
    }
    headers = {k: v for k, v in headers.items() if v}

    # --- authentication ----------------------------------------------------------
    auth = _auth_results(msg)
    if auth["spf"] == "fail":
        flag("High", 20, "SPF check failed", "Sending server not authorised for the envelope domain")
    elif auth["spf"] == "softfail":
        flag("Medium", 10, "SPF soft-fail", "Domain discourages but does not forbid this sender")
    if auth["dkim"] == "fail":
        flag("High", 15, "DKIM signature failed", "Message may have been altered or forged")
    elif auth["dkim"] in {"none"}:
        flag("Low", 5, "No DKIM signature", "")
    if auth["dmarc"] == "fail":
        flag("High", 20, "DMARC check failed", "From-domain alignment failed")
    if all(v is None for v in auth.values()):
        flag("Low", 5, "No SPF/DKIM/DMARC results in headers",
             "Authentication could not be verified (headers may be stripped or absent)")

    # --- identity mismatches -----------------------------------------------------
    if reply_dom and from_dom and _base_domain(reply_dom) != _base_domain(from_dom):
        flag("Medium", 15, "Reply-To domain differs from From domain", f"{from_dom} vs {reply_dom}")
    if rpath_dom and from_dom and _base_domain(rpath_dom) != _base_domain(from_dom):
        flag("Medium", 10, "Return-Path domain differs from From domain", f"{from_dom} vs {rpath_dom}")
    dn = (display_name or "").lower()
    if "@" in dn and _addr_domain(display_name) and _addr_domain(display_name) != from_dom:
        flag("High", 25, "Display name contains a different email address", display_name)
    else:
        for brand in BRANDS:
            if brand in dn and brand not in from_dom:
                flag("High", 25, f"Possible brand impersonation ('{brand}' in display name)",
                     f"Display name '{display_name}' but sender domain is {from_dom}")
                break

    # --- routing -----------------------------------------------------------------
    hops, timeline = [], []
    for raw in reversed(msg.get_all("Received", [])):
        raw = " ".join(str(raw).split())
        ips = [ip for ip in IPV4_RE.findall(raw) if is_ip(ip)]
        by = re.search(r"\bby\s+(\S+)", raw)
        frm = re.search(r"\bfrom\s+(\S+)", raw)
        date_s = raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
        iso = _to_utc_iso(_parse_date(date_s)) if date_s else None
        hops.append({"from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
                     "ips": ips, "timestamp_utc": iso or ""})
        if iso:
            timeline.append({"timestamp": iso, "source": "email", "event": "Mail relayed",
                             "detail": f"{frm.group(1) if frm else '?'} -> {by.group(1) if by else '?'}", "severity": "Info"})
    origin_ip = next((ip for h in hops for ip in h["ips"] if is_public_ip(ip)), "")

    # --- bodies, links and attachments --------------------------------------------
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname, disp = part.get_filename(), part.get_content_disposition()
        if fname or disp == "attachment":
            if len(attachments) >= 20:
                continue
            payload = part.get_payload(decode=True) or b""
            res = analyze_file(fname or "unnamed", payload)
            attachments.append({
                "filename": fname or "unnamed", "size": res["size"], "sha256": res["hashes"]["sha256"],
                "detected_type": res["detected_type"], "risk": res["risk"], "score": res["score"],
                "indicators": res["indicators"],
            })
            continue
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:  # noqa: BLE001 - malformed encodings are common in phishing
                content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            (html_parts if ctype == "text/html" else text_parts).append(content)

    plain = "\n".join(text_parts)
    html_text = re.sub(r"<[^>]+>", " ", "\n".join(html_parts))
    body_text = plain + "\n" + html_text

    link_parser = _LinkParser()
    for html in html_parts:
        try:
            link_parser.feed(html)
        except Exception:  # noqa: BLE001
            pass

    urls: dict[str, dict] = {}
    for href, label in link_parser.links:
        if not href.lower().startswith(("http://", "https://")):
            continue
        entry = urls.setdefault(href, {"url": href, "anchor_text": "", "flags": _url_flags(href)})
        if label:
            entry["anchor_text"] = label
            label_host = _host(label) if re.search(r"(?i)(https?://|www\.|\b[a-z0-9-]+\.[a-z]{2,}\b)", label) else ""
            href_host = _host(href)
            if label_host and href_host and _base_domain(label_host) != _base_domain(href_host):
                entry["flags"].append(f"Link text shows {label_host} but goes to {href_host}")
    for u in URL_RE.findall(body_text):
        u = u.rstrip(".,;:!?)]}>'\"")
        urls.setdefault(u, {"url": u, "anchor_text": "", "flags": _url_flags(u)})

    mismatch_count = ip_url = shortener = punycode = at_url = tld_flag = 0
    for entry in urls.values():
        for f in entry["flags"]:
            if f.startswith("Link text shows"):
                mismatch_count += 1
                if mismatch_count <= 2:
                    flag("High", 25, "Deceptive link (text and destination differ)", f"{entry['anchor_text']} -> {entry['url']}")
            elif f == "IP-address host" and not ip_url:
                ip_url = 1
                flag("High", 20, "Link points to a raw IP address", entry["url"])
            elif f == "URL shortener" and not shortener:
                shortener = 1
                flag("Medium", 10, "URL shortener hides final destination", entry["url"])
            elif f.startswith("Punycode") and not punycode:
                punycode = 1
                flag("Medium", 15, "Punycode domain (possible look-alike)", entry["url"])
            elif f.startswith("Credentials") and not at_url:
                at_url = 1
                flag("Medium", 15, "URL contains '@' (credential-style obfuscation)", entry["url"])
            elif f.startswith("Frequently abused") and not tld_flag:
                tld_flag = 1
                flag("Low", 5, f, entry["url"])

    for att in attachments:
        if att["risk"] in ("High", "Critical"):
            flag("High", 30, f"High-risk attachment: {att['filename']}", f"{att['detected_type']}, score {att['score']}")
        elif att["risk"] == "Medium":
            flag("Medium", 15, f"Suspicious attachment: {att['filename']}", f"{att['detected_type']}, score {att['score']}")

    lowered = body_text.lower() + " " + get("Subject").lower()
    hits = [k for k in URGENCY if k in lowered]
    if hits:
        flag("Low", min(15, 5 * len(hits)), "Urgency / social-engineering language", ", ".join(hits[:6]))

    # --- timeline & IOCs ----------------------------------------------------------
    sent = _to_utc_iso(_parse_date(headers.get("Date", "")))
    if sent:
        timeline.append({"timestamp": sent, "source": "email", "event": "Email sent (Date header)",
                         "detail": headers.get("Subject", ""), "severity": "Info"})

    header_ips = {ip for h in hops for ip in h["ips"] if is_public_ip(ip)}
    iocs = merge_iocs(
        extract_iocs(body_text),
        {"urls": list(urls), "ips": sorted(header_ips),
         "hashes": [a["sha256"] for a in attachments],
         "emails": [e for e in {from_addr.lower(), _addr_domain(reply_h) and parseaddr(reply_h)[1].lower()} if e]},
    )
    for u in urls:
        host = _host(u)
        if host and not is_ip(host):
            iocs["domains"] = sorted(set(iocs["domains"]) | {host})

    score = min(100, score)
    return {
        "headers": headers,
        "authentication": auth,
        "routing": hops,
        "origin_ip": origin_ip,
        "urls": list(urls.values()),
        "attachments": attachments,
        "indicators": indicators,
        "score": score,
        "risk": risk_label(score),
        "iocs": iocs,
        "timeline": timeline,
        "body_preview": body_text.strip()[:1500],
    }
