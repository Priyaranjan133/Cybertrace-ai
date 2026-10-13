"""Extract indicators of compromise (IOCs) from free text."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`]+")
IPV4_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b")
HASH_RE = re.compile(r"(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b")

# File extensions that look like TLDs but almost never are in practice.
FALSE_TLDS = {
    "exe", "dll", "txt", "log", "json", "png", "jpg", "jpeg", "gif", "py", "js",
    "html", "htm", "css", "pdf", "doc", "docx", "xls", "xlsx", "zip", "xml", "csv",
    "sh", "bat", "ps1", "php", "tmp", "bin", "dat", "cfg", "ini", "md", "yml", "yaml",
}

IOC_KINDS = ("ips", "domains", "urls", "hashes", "emails")


def refang(text: str) -> str:
    """Undo common defanging such as hxxp:// and [.]"""
    text = re.sub(r"(?i)hxxp", "http", text)
    for a, b in (("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[@]", "@"), ("[at]", "@")):
        text = text.replace(a, b)
    return text


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# Documentation ranges (RFC 5737) are not "global" per Python, but treating them as
# routable keeps the bundled demo realistic. Real mail never uses them.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global or any(ip in net for net in _DOC_NETS if ip.version == net.version)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _plausible_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld not in FALSE_TLDS and len(domain) > 3


def extract_iocs(text: str) -> dict:
    """Return {'ips','domains','urls','hashes','emails'} as sorted lists."""
    text = refang(text or "")
    urls = {u.rstrip(".,;:!?)]}>'\"") for u in URL_RE.findall(text)}
    emails = {e.lower() for e in EMAIL_RE.findall(text)}
    hashes = {h.lower() for h in HASH_RE.findall(text)}
    ips = {ip for ip in IPV4_RE.findall(text) if _valid_ipv4(ip)}

    work = URL_RE.sub(" ", text)
    work = EMAIL_RE.sub(lambda m: " " + m.group().split("@", 1)[1] + " ", work)
    domains = {d.lower() for d in DOMAIN_RE.findall(work) if _plausible_domain(d)}

    for url in urls:
        try:
            host = urlparse(url).hostname
        except ValueError:
            host = None
        if not host:
            continue
        if is_ip(host):
            ips.add(host)
        elif _plausible_domain(host):
            domains.add(host.lower())

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": sorted(hashes),
        "emails": sorted(emails),
    }


def merge_iocs(*sets: dict) -> dict:
    merged = {k: set() for k in IOC_KINDS}
    for s in sets:
        for k in IOC_KINDS:
            merged[k].update((s or {}).get(k, []))
    return {k: sorted(v) for k, v in merged.items()}
