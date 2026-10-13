"""Static file forensics. Files are NEVER executed, opened by an OS handler or extracted to disk."""
from __future__ import annotations

import io
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

from modules.common import risk_label
from modules.evidence_integrity import compute_hashes
from modules.ioc_extractor import extract_iocs

# (magic bytes, label, expected extensions, family)
SIGNATURES = [
    (b"MZ", "Windows executable (PE)", {"exe", "dll", "sys", "scr", "ocx", "cpl", "efi"}, "pe"),
    (b"\x7fELF", "ELF executable", {"elf", "so", "bin", "o", "out"}, "elf"),
    (b"%PDF-", "PDF document", {"pdf"}, "pdf"),
    (b"PK\x03\x04", "ZIP container (zip / Office OOXML / jar / apk)",
     {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk", "odt", "ods", "odp", "xpi", "whl"}, "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound file (legacy Office / MSI)",
     {"doc", "xls", "ppt", "msi", "msg", "xlt", "dot"}, "ole"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {"png"}, "image"),
    (b"\xff\xd8\xff", "JPEG image", {"jpg", "jpeg"}, "image"),
    (b"GIF87a", "GIF image", {"gif"}, "image"),
    (b"GIF89a", "GIF image", {"gif"}, "image"),
    (b"Rar!\x1a\x07", "RAR archive", {"rar"}, "archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {"7z"}, "archive"),
    (b"\x1f\x8b", "GZIP archive", {"gz", "tgz"}, "archive"),
    (b"SQLite format 3\x00", "SQLite database", {"db", "sqlite", "sqlite3"}, "other"),
    (b"{\\rtf", "RTF document", {"rtf"}, "rtf"),
    (b"MSCF", "Microsoft Cabinet archive", {"cab"}, "archive"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)", {"lnk"}, "other"),
]

EXECUTABLE_EXTS = {"exe", "scr", "pif", "com", "hta", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "bat", "cmd", "msi", "jar", "cpl"}
SUSPICIOUS_EXTS = EXECUTABLE_EXTS | {"lnk", "iso", "img", "dll", "reg", "docm", "xlsm", "pptm", "vhd", "chm"}
DOC_LIKE_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "rtf", "csv"}
DOUBLE_EXT_RE = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|rtf|csv)\.(exe|scr|bat|cmd|js|jse|vbs|vbe|ps1|com|hta|pif|lnk)$")

SCRIPT_PATTERNS = [
    (rb"<script", "HTML <script> tag"),
    (rb"powershell", "PowerShell reference"),
    (rb"cmd\.exe", "cmd.exe reference"),
    (rb"wscript\.shell", "WScript.Shell (script execution)"),
    (rb"frombase64string", "Base64 decode call (common in droppers)"),
    (rb"invoke-expression|\biex\b", "Invoke-Expression (PowerShell)"),
    (rb"autoopen|auto_open|document_open|workbook_open", "Office auto-execute macro"),
    (rb"eval\s*\(", "eval() call"),
]
PDF_PATTERNS = [
    (rb"/JavaScript|/JS\b", "PDF embedded JavaScript"),
    (rb"/OpenAction|/AA\b", "PDF automatic action on open"),
    (rb"/Launch", "PDF /Launch action"),
    (rb"/EmbeddedFile", "PDF embedded file"),
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def identify_type(data: bytes) -> tuple[str, set | None, str]:
    for magic, label, exts, family in SIGNATURES:
        if data.startswith(magic):
            return label, exts, family
    sample = data[:4096]
    if sample:
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(sample) >= 0.95:
            return "Text / script", None, "text"
    return "Unknown binary", None, "other"


def _ooxml_metadata(zf: zipfile.ZipFile) -> dict:
    meta: dict = {}

    def grab(name: str, tags: dict) -> None:
        if name not in zf.namelist():
            return
        try:
            xml = zf.read(name)[:200_000].decode("utf-8", "replace")
        except Exception:
            return
        for tag, label in tags.items():
            m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml, re.S)
            if m and m.group(1).strip():
                meta[label] = m.group(1).strip()

    grab("docProps/core.xml", {"dc:creator": "Author", "cp:lastModifiedBy": "Last modified by",
                               "dcterms:created": "Created", "dcterms:modified": "Modified", "dc:title": "Title"})
    grab("docProps/app.xml", {"Application": "Application", "Company": "Company"})
    return meta


def _pdf_metadata(data: bytes) -> dict:
    meta: dict = {}
    blob = data[:65536] + data[-65536:]
    for key in ("Title", "Author", "Creator", "Producer", "CreationDate", "ModDate"):
        m = re.search(rb"/" + key.encode() + rb"\s*\((.*?)\)", blob, re.S)
        if m:
            meta[key] = m.group(1).decode("latin-1", "replace")[:200]
    return meta


def _analyze_zip(data: bytes) -> tuple[dict, dict, list]:
    """Inspect (never extract) a ZIP. Returns (archive_info, metadata, indicators)."""
    indicators: list = []
    info: dict = {"entries": [], "total_entries": 0}
    meta: dict = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        indicators.append(("Medium", 15, "Corrupt or truncated ZIP structure", "BadZipFile"))
        return info, meta, indicators

    infos = zf.infolist()
    info["total_entries"] = len(infos)
    total_unc = sum(i.file_size for i in infos)
    total_comp = sum(i.compress_size for i in infos) or 1
    info["uncompressed_bytes"] = total_unc
    info["compression_ratio"] = round(total_unc / total_comp, 1)

    encrypted = traversal = nested = False
    exec_inside: list = []
    macros = False
    for i in infos[:5000]:
        ext = Path(i.filename).suffix.lower().lstrip(".")
        enc = bool(i.flag_bits & 0x1)
        sus = ext in SUSPICIOUS_EXTS
        encrypted |= enc
        if i.filename.startswith("/") or ".." in Path(i.filename).parts:
            traversal = True
        if ext in {"zip", "rar", "7z", "gz", "iso"}:
            nested = True
        if ext in EXECUTABLE_EXTS or ext == "dll":
            exec_inside.append(i.filename)
        if i.filename.lower().endswith("vbaproject.bin"):
            macros = True
        if len(info["entries"]) < 200:
            info["entries"].append({"name": i.filename, "size": i.file_size, "compressed": i.compress_size,
                                    "encrypted": enc, "suspicious": sus})

    meta = _ooxml_metadata(zf)
    if encrypted:
        indicators.append(("Medium", 20, "Password-protected entries inside archive", "Cannot be inspected without the password"))
    if exec_inside:
        indicators.append(("High", 30, "Executable/script content inside archive", ", ".join(exec_inside[:5])))
    if macros:
        indicators.append(("High", 30, "VBA macro project present in Office file", "vbaProject.bin"))
    if traversal:
        indicators.append(("High", 30, "Path traversal in archive entry names", "Entries contain '..' or absolute paths"))
    if total_unc > 500_000_000 and total_unc / total_comp > 100:
        indicators.append(("Medium", 20, "Possible decompression bomb", f"ratio {total_unc / total_comp:.0f}:1"))
    if nested:
        indicators.append(("Low", 5, "Nested archive/disk-image inside archive", ""))
    return info, meta, indicators


def analyze_file(filename: str, data: bytes) -> dict:
    hashes = compute_hashes(data)
    ext = Path(filename).suffix.lower().lstrip(".")
    label, expected, family = identify_type(data)
    entropy = round(_entropy(data[:1_048_576]), 3)

    raw: list = []  # (severity, points, finding, evidence)
    metadata: dict = {}
    archive = None

    # --- extension vs content --------------------------------------------------
    mismatch = False
    if expected is not None and ext and ext not in expected:
        mismatch = True
    if family == "text" and ext in {"exe", "dll", "pdf", "png", "jpg", "jpeg", "gif", "zip", "docx", "xlsx"}:
        mismatch = True
    if mismatch:
        if family in {"pe", "elf"} and (ext in DOC_LIKE_EXTS or not ext):
            raw.append(("High", 60, "Executable disguised with a non-executable extension", f".{ext} but content is {label}"))
        else:
            raw.append(("Medium", 20, "File extension does not match file content", f".{ext} but content is {label}"))
    elif family in {"pe", "elf"}:
        raw.append(("Medium", 15, "Executable content", label))

    # --- name based checks -----------------------------------------------------
    if "\u202e" in filename:
        raw.append(("High", 40, "Right-to-left override character in filename", "Used to hide the real extension"))
    if DOUBLE_EXT_RE.search(filename):
        raw.append(("High", 35, "Double extension (document name hiding an executable)", filename))
    if ext in SUSPICIOUS_EXTS:
        sev, pts = ("High", 25) if ext in EXECUTABLE_EXTS else ("Medium", 15)
        raw.append((sev, pts, f"Potentially dangerous file extension (.{ext})", filename))

    # --- content patterns ------------------------------------------------------
    head = data[:5_000_000]
    script_hits = [desc for pat, desc in SCRIPT_PATTERNS if re.search(pat, head, re.I)]
    for desc in script_hits[:3]:
        raw.append(("Medium", 10, f"Embedded script indicator: {desc}", ""))
    if family == "pdf":
        for pat, desc in PDF_PATTERNS:
            if re.search(pat, head):
                raw.append(("High" if "JavaScript" in desc or "Launch" in desc else "Medium",
                            20 if "JavaScript" in desc or "Launch" in desc else 10, desc, ""))
        metadata = _pdf_metadata(data)

    if family not in {"zip", "image", "archive"} and entropy > 7.5 and len(data) > 2048:
        raw.append(("Medium", 15, "Very high entropy (packed or encrypted content?)", f"entropy {entropy}/8"))

    if family == "zip":
        archive, metadata, zind = _analyze_zip(data)
        raw.extend(zind)

    # --- scoring -----------------------------------------------------------------
    score = min(100, sum(r[1] for r in raw))
    indicators = [{"severity": s, "finding": f, "evidence": e} for s, _, f, e in raw]

    iocs = extract_iocs(data[:1_000_000].decode("utf-8", "ignore")) if family == "text" else {
        "ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}
    iocs["hashes"] = sorted(set(iocs["hashes"]) | {hashes["sha256"]})

    return {
        "filename": filename,
        "size": len(data),
        "hashes": hashes,
        "detected_type": label,
        "claimed_extension": ext,
        "extension_matches": not mismatch,
        "entropy": entropy,
        "metadata": metadata,
        "archive": archive,
        "indicators": indicators,
        "score": score,
        "risk": risk_label(score),
        "iocs": iocs,
        "timeline": [],
    }
