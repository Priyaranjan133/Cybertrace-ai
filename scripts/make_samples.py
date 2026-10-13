"""Generate harmless demo evidence (RFC 5737 documentation IPs, .example domains).

Run:  python scripts/make_samples.py
The 'attachment' is a dummy file that merely starts with the bytes 'MZ' - it contains no code.
"""
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timezone, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_data"
OUT.mkdir(exist_ok=True)
ATTACKER = "203.0.113.45"   # TEST-NET-3: reserved for documentation
USER_IP = "198.51.100.7"    # TEST-NET-2


def make_eml() -> None:
    msg = EmailMessage()
    msg["From"] = '"PayPal Security" <security@paypa1-support.example>'
    msg["To"] = "alice@acme-corp.example"
    msg["Reply-To"] = "collect@mailbox-drop.example"
    msg["Return-Path"] = "<bounce@mailer.paypa1-support.example>"
    msg["Subject"] = "URGENT: Verify your account within 24 hours"
    msg["Date"] = format_datetime(datetime(2026, 10, 12, 2, 41, 7, tzinfo=timezone.utc))
    msg["Message-ID"] = "<20261012024107.1A2B3C@paypa1-support.example>"
    msg["Authentication-Results"] = "mx.acme-corp.example; spf=fail smtp.mailfrom=paypa1-support.example; dkim=none; dmarc=fail header.from=paypa1-support.example"
    msg["Received"] = ("from mail.acme-corp.example (mx1.acme-corp.example [192.0.2.10]) by mx.acme-corp.example with ESMTP; "
                       + format_datetime(datetime(2026, 10, 12, 2, 41, 12, tzinfo=timezone.utc)))
    msg["Received"] = (f"from unknown-host ([{ATTACKER}]) by mail.acme-corp.example with SMTP; "
                       + format_datetime(datetime(2026, 10, 12, 2, 41, 9, tzinfo=timezone.utc)))
    msg.set_content("Your account has been suspended due to unusual activity. Verify your account immediately: http://203.0.113.45/login.php")
    msg.add_alternative(
        "<html><body><p>Dear customer,</p><p>Your account has been <b>suspended</b> due to unusual activity. "
        "Act now - <a href='http://203.0.113.45/login.php'>https://www.paypal.com/verify</a></p>"
        "<p>Invoice attached for your records.</p></body></html>", subtype="html")
    msg.add_attachment(b"MZ" + b"\x00" * 64 + b"DUMMY FILE FOR DEMO - NO CODE", maintype="application",
                       subtype="octet-stream", filename="Invoice_8841.pdf.exe")
    (OUT / "phishing_sample.eml").write_bytes(bytes(msg))


def make_log() -> None:
    lines = []
    day1 = datetime(2026, 10, 11, 9, 12, 44)
    for i, user in enumerate(["alice", "bob", "alice", "carol"]):
        t = day1 + timedelta(hours=i * 2)
        lines.append(f"{t:%b %e %H:%M:%S} web01 sshd[10{i}1]: Accepted publickey for {user} from {USER_IP} port 5112{i} ssh2")
    lines.append(f"{datetime(2026, 10, 11, 16, 5, 2):%b %e %H:%M:%S} web01 sshd[1101]: Failed password for alice from {USER_IP} port 51190 ssh2")
    t = datetime(2026, 10, 12, 3, 11, 2)
    users = ["admin", "root", "test", "oracle", "ubuntu", "postgres"]
    for i in range(30):
        lines.append(f"{t + timedelta(seconds=7 * i):%b %e %H:%M:%S} web01 sshd[2{i:03d}]: Failed password for "
                     f"{'invalid user ' if users[i % 6] != 'root' else ''}{users[i % 6]} from {ATTACKER} port {40100 + i} ssh2")
    lines += [
        f"Oct 12 03:15:41 web01 sshd[2301]: Accepted password for root from {ATTACKER} port 40222 ssh2",
        "Oct 12 03:16:10 web01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m svc_backup",
        "Oct 12 03:16:12 web01 useradd[2310]: new user: name=svc_backup, UID=1005, GID=1005, home=/home/svc_backup, shell=/bin/bash",
        "Oct 12 03:16:30 web01 usermod[2315]: add 'svc_backup' to group 'sudo'",
        f"Oct 12 09:30:11 web01 sshd[2500]: Accepted publickey for alice from {USER_IP} port 51300 ssh2",
    ]
    (OUT / "auth_sample.log").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    make_eml()
    make_log()
    print("Wrote", [p.name for p in OUT.iterdir()])
