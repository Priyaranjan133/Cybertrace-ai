"""SQLite persistence for cases, evidence, analysis results and a hash-chained audit log."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from modules.evidence_integrity import compute_hashes, verify_file

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("CYBERTRACE_DATA", BASE_DIR / "data"))
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "cybertrace.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
    case_id TEXT PRIMARY KEY, title TEXT NOT NULL, investigator TEXT, status TEXT DEFAULT 'Open',
    notes TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, filename TEXT, evidence_type TEXT,
    size INTEGER, sha256 TEXT, md5 TEXT, sha1 TEXT, stored_path TEXT, source_note TEXT,
    acquired_by TEXT, acquired_at TEXT, reviewed INTEGER DEFAULT 0, verified INTEGER, verified_at TEXT);
CREATE TABLE IF NOT EXISTS results(
    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, evidence_id INTEGER, module TEXT,
    risk TEXT, summary TEXT, details TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, actor TEXT, action TEXT, detail TEXT,
    timestamp TEXT, prev_hash TEXT, entry_hash TEXT);
"""


class IntegrityError(Exception):
    """Raised when stored evidence no longer matches its acquisition hash."""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as c:
        c.executescript(SCHEMA)


# --------------------------------------------------------------------------- audit
def _entry_hash(prev: str, case_id, actor, action, detail, ts) -> str:
    return hashlib.sha256(f"{prev}|{case_id}|{actor}|{action}|{detail}|{ts}".encode()).hexdigest()


def _log(conn, case_id, actor, action, detail="") -> None:
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["entry_hash"] if row else "GENESIS"
    ts = now_iso()
    conn.execute(
        "INSERT INTO audit_log(case_id, actor, action, detail, timestamp, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?)",
        (case_id, actor, action, detail, ts, prev, _entry_hash(prev, case_id, actor, action, detail, ts)))


def log_action(case_id, actor, action, detail="") -> None:
    with connect() as c:
        _log(c, case_id, actor, action, detail)


def get_audit(case_id: str | None = None, limit: int = 500) -> list[dict]:
    with connect() as c:
        if case_id:
            rows = c.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY id DESC LIMIT ?", (case_id, limit)).fetchall()
        else:
            rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def verify_audit_chain() -> tuple[bool, int | None, int]:
    """Return (ok, first_bad_entry_id, entries_checked). Detects edited, deleted or reordered rows."""
    with connect() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    prev = "GENESIS"
    for r in rows:
        expected = _entry_hash(prev, r["case_id"], r["actor"], r["action"], r["detail"], r["timestamp"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return False, r["id"], len(rows)
        prev = r["entry_hash"]
    return True, None, len(rows)


# --------------------------------------------------------------------------- cases
def create_case(title: str, investigator: str, notes: str = "", actor: str = "analyst") -> str:
    with connect() as c:
        n = c.execute("SELECT COUNT(*) FROM cases").fetchone()[0] + 1
        year = datetime.now(timezone.utc).year
        case_id = f"CASE-{year}-{n:04d}"
        while c.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
            n += 1
            case_id = f"CASE-{year}-{n:04d}"
        c.execute("INSERT INTO cases(case_id,title,investigator,status,notes,created_at) VALUES (?,?,?,?,?,?)",
                  (case_id, title, investigator, "Open", notes, now_iso()))
        _log(c, case_id, actor, "case_created", title)
    return case_id


def list_cases() -> list[dict]:
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM cases ORDER BY created_at DESC, case_id DESC")]


def get_case(case_id: str | None) -> dict | None:
    if not case_id:
        return None
    with connect() as c:
        row = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    return dict(row) if row else None


def update_case(case_id: str, status: str, notes: str, actor: str) -> None:
    with connect() as c:
        c.execute("UPDATE cases SET status=?, notes=? WHERE case_id=?", (status, notes, case_id))
        _log(c, case_id, actor, "case_updated", f"status={status}")


# --------------------------------------------------------------------------- evidence
def add_evidence(case_id: str, filename: str, data: bytes, evidence_type: str, acquired_by: str, source_note: str = "") -> int:
    hashes = compute_hashes(data)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "evidence.bin"
    folder = EVIDENCE_DIR / case_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{hashes['sha256'][:16]}_{safe}"
    if not path.exists():
        path.write_bytes(data)
        try:
            os.chmod(path, 0o444)  # read-only: evidence is never modified in place
        except OSError:
            pass
    with connect() as c:
        cur = c.execute(
            "INSERT INTO evidence(case_id,filename,evidence_type,size,sha256,md5,sha1,stored_path,source_note,acquired_by,acquired_at,verified,verified_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, filename, evidence_type, len(data), hashes["sha256"], hashes["md5"], hashes["sha1"],
             str(path.relative_to(DATA_DIR)), source_note, acquired_by, now_iso(), 1, now_iso()))
        ev_id = cur.lastrowid
        _log(c, case_id, acquired_by, "evidence_acquired", f"E{ev_id} {filename} sha256={hashes['sha256']}")
    return ev_id


def list_evidence(case_id: str | None = None) -> list[dict]:
    with connect() as c:
        if case_id:
            rows = c.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM evidence ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_evidence(evidence_id: int) -> dict | None:
    with connect() as c:
        row = c.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    return dict(row) if row else None


def read_evidence_bytes(evidence_id: int) -> bytes:
    """Read stored evidence, re-checking its SHA-256 first."""
    ev = get_evidence(evidence_id)
    if ev is None:
        raise KeyError(f"Evidence {evidence_id} not found")
    path = DATA_DIR / ev["stored_path"]
    ok, actual = verify_file(path, ev["sha256"])
    if not ok:
        log_action(ev["case_id"], "system", "integrity_failure", f"E{evidence_id} expected={ev['sha256']} actual={actual}")
        raise IntegrityError(f"Evidence E{evidence_id} failed integrity verification (actual: {actual}).")
    return path.read_bytes()


def verify_all(case_id: str | None = None, actor: str = "system") -> list[dict]:
    report = []
    for ev in list_evidence(case_id):
        ok, actual = verify_file(DATA_DIR / ev["stored_path"], ev["sha256"])
        report.append({"id": ev["id"], "filename": ev["filename"], "ok": ok,
                       "status": "OK" if ok else ("MISSING" if actual == "MISSING" else "HASH MISMATCH"),
                       "expected": ev["sha256"], "actual": actual})
    with connect() as c:
        for r in report:
            c.execute("UPDATE evidence SET verified=?, verified_at=? WHERE id=?", (1 if r["ok"] else 0, now_iso(), r["id"]))
        failed = [f"E{r['id']}" for r in report if not r["ok"]]
        _log(c, case_id, actor, "integrity_check", f"{len(report)} item(s) checked; failures: {', '.join(failed) or 'none'}")
    return report


def mark_reviewed(evidence_ids: list[int], actor: str) -> None:
    with connect() as c:
        for i in evidence_ids:
            c.execute("UPDATE evidence SET reviewed=1 WHERE id=?", (i,))
            row = c.execute("SELECT case_id FROM evidence WHERE id=?", (i,)).fetchone()
            _log(c, row["case_id"] if row else None, actor, "evidence_reviewed", f"E{i}")


# --------------------------------------------------------------------------- results
def save_result(case_id: str, evidence_id: int, module: str, risk: str, summary: str, details: dict, actor: str) -> None:
    with connect() as c:
        c.execute("DELETE FROM results WHERE evidence_id=? AND module=?", (evidence_id, module))
        c.execute("INSERT INTO results(case_id,evidence_id,module,risk,summary,details,created_at) VALUES (?,?,?,?,?,?,?)",
                  (case_id, evidence_id, module, risk, summary, json.dumps(details, default=str), now_iso()))
        _log(c, case_id, actor, "analysis_run", f"{module} on E{evidence_id}: risk={risk}")


def get_results(case_id: str, evidence_id: int | None = None, module: str | None = None) -> list[dict]:
    q, args = "SELECT * FROM results WHERE case_id=?", [case_id]
    if evidence_id is not None:
        q, args = q + " AND evidence_id=?", args + [evidence_id]
    if module:
        q, args = q + " AND module=?", args + [module]
    with connect() as c:
        rows = c.execute(q + " ORDER BY id", args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details"] or "{}")
        out.append(d)
    return out


# --------------------------------------------------------------------------- stats
def stats() -> dict:
    with connect() as c:
        active = c.execute("SELECT COUNT(*) FROM cases WHERE status != 'Closed'").fetchone()[0]
        total = c.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        pending = c.execute("SELECT COUNT(*) FROM evidence WHERE reviewed=0").fetchone()[0]
        verified = c.execute("SELECT COUNT(*) FROM evidence WHERE verified=1").fetchone()[0]
    return {"active_cases": active, "evidence": total, "pending_review": pending,
            "verified_pct": round(100 * verified / total) if total else None}
