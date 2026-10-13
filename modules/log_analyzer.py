"""Log forensics: Linux auth/syslog and CSV exports (e.g. Windows Security events)."""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone

import pandas as pd

from modules.common import max_risk, risk_rank

EVENT_COLUMNS = ["timestamp", "host", "user", "ip", "event_type", "message", "source"]

WIN_EVENTS = {
    "4624": "login_success", "4625": "login_failed", "4672": "privilege_use",
    "4720": "account_created", "4728": "privilege_change", "4732": "privilege_change",
    "4756": "privilege_change", "1102": "log_cleared", "4719": "policy_change",
    "4740": "account_lockout",
}
EVENT_SEVERITY = {
    "log_cleared": "High", "privilege_change": "High", "account_created": "Medium",
    "policy_change": "Medium", "account_lockout": "Low", "privilege_use": "Low",
    "login_success": "Info", "login_failed": "Info", "other": "Info",
}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
FAILED_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
PAM_FAIL_RE = re.compile(r"authentication failure;.*rhost=(?P<ip>\S+)(?:.*user=(?P<user>\S+))?")
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*COMMAND=")
NEWUSER_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUP_RE = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")

CSV_ALIASES = {
    "timestamp": ["timestamp", "time", "timecreated", "datetime", "date", "eventtime", "utctime"],
    "user": ["user", "username", "targetusername", "account", "accountname", "subjectusername"],
    "ip": ["ip", "ipaddress", "sourceip", "srcip", "src", "sourcenetworkaddress", "clientip", "remoteip"],
    "event": ["eventid", "event", "eventtype", "action", "status"],
    "message": ["message", "description", "details", "msg"],
    "host": ["host", "hostname", "computer", "computername", "machine"],
}


def classify(text: str) -> str:
    t = text.lower()
    if "log cleared" in t or "audit log was cleared" in t:
        return "log_cleared"
    if any(k in t for k in ("added to group", "member added", "to group")):
        return "privilege_change"
    if "account created" in t or "new user" in t or "user created" in t:
        return "account_created"
    if any(k in t for k in ("fail", "invalid", "denied", "incorrect")):
        return "login_failed"
    if "accepted" in t or "success" in t:
        return "login_success"
    if "sudo" in t or "privilege" in t or "elevat" in t:
        return "privilege_use"
    return "other"


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def parse_syslog(text: str, year: int) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        m = SYSLOG_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(f"{year} {m['mon']} {int(m['day'])} {m['time']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        msg, proc = m["msg"], m["proc"]
        user = ip = None
        etype = "other"
        if (mm := FAILED_RE.search(msg)) or (mm := INVALID_RE.search(msg)):
            etype, user, ip = "login_failed", mm["user"], mm["ip"]
        elif mm := PAM_FAIL_RE.search(msg):
            etype, ip, user = "login_failed", mm["ip"], mm.groupdict().get("user")
        elif mm := ACCEPTED_RE.search(msg):
            etype, user, ip = "login_success", mm["user"], mm["ip"]
        elif proc == "sudo" and (mm := SUDO_RE.match(msg)):
            etype, user = "privilege_use", mm["user"]
        elif mm := NEWUSER_RE.search(msg):
            etype, user = "account_created", mm["user"]
        elif mm := GROUP_RE.search(msg):
            etype, user = "privilege_change", mm["user"]
        rows.append({"timestamp": ts, "host": m["host"], "user": user, "ip": ip,
                     "event_type": etype, "message": msg[:300], "source": "syslog"})
    df = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def parse_csv(text: str) -> pd.DataFrame:
    raw = pd.read_csv(io.StringIO(text), dtype=str, on_bad_lines="skip")
    cols = {_norm(c): c for c in raw.columns}

    def pick(key: str):
        for alias in CSV_ALIASES[key]:
            if alias in cols:
                return cols[alias]
        return None

    ts_c, user_c, ip_c, ev_c, msg_c, host_c = (pick(k) for k in ("timestamp", "user", "ip", "event", "message", "host"))
    if ts_c is None:
        raise ValueError("CSV needs a timestamp column (e.g. 'timestamp', 'TimeCreated', 'Date').")
    out = pd.DataFrame({
        "timestamp": pd.to_datetime(raw[ts_c], errors="coerce", utc=True),
        "host": raw[host_c] if host_c else None,
        "user": raw[user_c] if user_c else None,
        "ip": raw[ip_c] if ip_c else None,
        "message": raw[msg_c] if msg_c else "",
        "source": "csv",
    })
    ev = raw[ev_c].fillna("") if ev_c else pd.Series([""] * len(raw))
    joined = ev.astype(str) + " " + out["message"].fillna("").astype(str)
    out["event_type"] = [WIN_EVENTS.get(str(e).strip(), classify(j)) for e, j in zip(ev, joined)]
    out = out.dropna(subset=["timestamp"])
    out["ip"] = out["ip"].where(out["ip"].notna() & ~out["ip"].isin(["-", "::1", "127.0.0.1", ""]), None)
    return out[EVENT_COLUMNS]


def parse_log(data: bytes, filename: str, year: int | None = None) -> pd.DataFrame:
    text = data.decode("utf-8", errors="replace")
    first = next((l for l in text.splitlines() if l.strip()), "")
    if filename.lower().endswith(".csv") or (first.count(",") >= 2 and not SYSLOG_RE.match(first)):
        df = parse_csv(text)
    else:
        df = parse_syslog(text, year or datetime.now(timezone.utc).year)
    return df.sort_values("timestamp").reset_index(drop=True)


def _iso(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect(df: pd.DataFrame, brute_threshold: int = 5, window_minutes: int = 10,
           offhours: tuple[int, int] = (0, 6), success_window_minutes: int = 60) -> list[dict]:
    findings: list[dict] = []
    if df.empty:
        return findings
    window = pd.Timedelta(minutes=window_minutes)
    after = pd.Timedelta(minutes=success_window_minutes)

    def add(sev, ftype, desc, ip=None, user=None, first=None, last=None, count=0):
        findings.append({"severity": sev, "type": ftype, "description": desc, "ip": ip, "user": user,
                         "first_seen": _iso(first) if first is not None else None,
                         "last_seen": _iso(last) if last is not None else None, "count": int(count)})

    fails = df[(df["event_type"] == "login_failed") & df["ip"].notna()]
    compromised_at: list[pd.Timestamp] = []
    for ip, grp in fails.groupby("ip"):
        ts = list(grp["timestamp"].sort_values())
        best, start, end, j = 0, None, None, 0
        for i in range(len(ts)):
            while ts[i] - ts[j] > window:
                j += 1
            if i - j + 1 > best:
                best, start, end = i - j + 1, ts[j], ts[i]
        if best < brute_threshold:
            continue
        in_win = grp[(grp["timestamp"] >= start) & (grp["timestamp"] <= end)]
        users = sorted(in_win["user"].dropna().unique())
        add("High" if best >= 20 else "Medium", "brute_force",
            f"{best} failed logins from {ip} within {window_minutes} min targeting {len(users)} account(s)",
            ip=ip, first=start, last=end, count=best)
        if len(users) >= 5:
            add("High", "password_spraying",
                f"{ip} attempted {len(users)} different accounts ({', '.join(users[:6])}{'...' if len(users) > 6 else ''})",
                ip=ip, first=start, last=end, count=len(in_win))
        wins = df[(df["event_type"] == "login_success") & (df["ip"] == ip)
                  & (df["timestamp"] >= start) & (df["timestamp"] <= end + after)]
        if not wins.empty:
            first_ok = wins["timestamp"].min()
            compromised_at.append(first_ok)
            who = ", ".join(sorted(wins["user"].dropna().unique()))
            add("Critical", "success_after_bruteforce",
                f"Successful login from {ip} (account: {who}) after {best} failures - possible credential compromise",
                ip=ip, user=who, first=first_ok, last=wins["timestamp"].max(), count=len(wins))

    for t0 in compromised_at:
        post = df[df["event_type"].isin(["privilege_change", "account_created", "privilege_use", "log_cleared"])
                  & (df["timestamp"] >= t0) & (df["timestamp"] <= t0 + after)]
        if not post.empty:
            kinds = ", ".join(sorted(post["event_type"].unique()))
            add("Critical", "post_compromise_activity",
                f"{len(post)} privileged/persistence event(s) within {success_window_minutes} min of the suspicious login ({kinds})",
                first=post["timestamp"].min(), last=post["timestamp"].max(), count=len(post))

    succ = df[df["event_type"] == "login_success"].copy()
    if not succ.empty:
        hours = succ["timestamp"].dt.hour
        s, e = offhours
        mask = (hours >= s) & (hours < e) if s <= e else (hours >= s) | (hours < e)
        for (user, ip), grp in succ[mask].groupby([succ["user"].fillna("?"), succ["ip"].fillna("?")]):
            add("Medium", "off_hours_login",
                f"Login during off-hours ({s:02d}:00-{e:02d}:00 UTC): {user} from {ip}",
                ip=None if ip == "?" else ip, user=user, first=grp["timestamp"].min(), last=grp["timestamp"].max(), count=len(grp))

    for etype, label in (("log_cleared", "Security/audit log cleared"), ("privilege_change", "Privilege or group membership change"),
                         ("account_created", "New account created"), ("policy_change", "Audit policy changed"),
                         ("privilege_use", "Elevated command execution (sudo / special privileges)"),
                         ("account_lockout", "Account lockout")):
        sub = df[df["event_type"] == etype]
        for user, grp in sub.groupby(sub["user"].fillna("(unknown)")):
            add(EVENT_SEVERITY[etype], etype, f"{label}: {user} ({len(grp)} event(s))", user=user,
                first=grp["timestamp"].min(), last=grp["timestamp"].max(), count=len(grp))

    findings.sort(key=lambda f: (-risk_rank(f["severity"]), f["first_seen"] or ""))
    return findings


def analyze_log(data: bytes, filename: str, year: int | None = None, **params) -> dict:
    df = parse_log(data, filename, year)
    findings = detect(df, **params)
    if df.empty:
        return {"stats": {"events": 0}, "findings": [], "indicators": [], "score": 0, "risk": "Info",
                "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
                "timeline": [], "events_by_hour": [], "failed_by_ip": [], "params": params,
                "note": "No parsable events found. Check the format (syslog auth.log or CSV with a timestamp column)."}

    hourly = df.assign(hour=df["timestamp"].dt.floor("h"))
    hourly["bucket"] = hourly["event_type"].map(lambda e: e if e in ("login_failed", "login_success") else "other")
    pivot = hourly.pivot_table(index="hour", columns="bucket", values="message", aggfunc="count", fill_value=0)
    for col in ("login_failed", "login_success", "other"):
        if col not in pivot:
            pivot[col] = 0
    events_by_hour = [{"hour": _iso(h), "failed": int(r["login_failed"]), "success": int(r["login_success"]), "other": int(r["other"])}
                      for h, r in pivot.iterrows()]
    failed_by_ip = (df[df["event_type"] == "login_failed"].groupby("ip").size().sort_values(ascending=False).head(10))

    timeline = [{"timestamp": f["first_seen"], "source": f"log:{filename}", "event": f["type"],
                 "detail": f["description"], "severity": f["severity"]} for f in findings if f["first_seen"]]
    interesting = df[~df["event_type"].isin(["login_failed", "other"])].head(1500)
    for _, r in interesting.iterrows():
        timeline.append({"timestamp": _iso(r["timestamp"]), "source": f"log:{filename}", "event": r["event_type"],
                         "detail": f"user={r['user'] or '-'} ip={r['ip'] or '-'}", "severity": EVENT_SEVERITY.get(r["event_type"], "Info")})

    top = max_risk([f["severity"] for f in findings])
    return {
        "stats": {
            "events": int(len(df)), "first": _iso(df["timestamp"].min()), "last": _iso(df["timestamp"].max()),
            "unique_ips": int(df["ip"].nunique()), "unique_users": int(df["user"].nunique()),
            "by_type": {k: int(v) for k, v in df["event_type"].value_counts().items()},
        },
        "findings": findings,
        "indicators": [],
        "score": min(100, 20 * risk_rank(top)),
        "risk": top,
        "iocs": {"ips": sorted(df["ip"].dropna().unique())[:500], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": timeline,
        "events_by_hour": events_by_hour,
        "failed_by_ip": [{"ip": ip, "count": int(c)} for ip, c in failed_by_ip.items()],
        "params": params,
    }
