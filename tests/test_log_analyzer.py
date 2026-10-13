import unittest
from pathlib import Path

from modules.log_analyzer import analyze_log

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "auth_sample.log"

CSV = b"""TimeCreated,EventID,TargetUserName,IpAddress
2026-10-12T10:00:00Z,4625,admin,203.0.113.5
2026-10-12T10:01:00Z,4625,admin,203.0.113.5
2026-10-12T10:02:00Z,4625,admin,203.0.113.5
2026-10-12T10:03:00Z,4625,admin,203.0.113.5
2026-10-12T10:04:00Z,4625,admin,203.0.113.5
2026-10-12T10:05:00Z,4624,admin,203.0.113.5
2026-10-12T10:06:00Z,1102,SYSTEM,-
"""


class LogTests(unittest.TestCase):
    def test_syslog_sample_detections(self):
        r = analyze_log(SAMPLE.read_bytes(), "auth_sample.log", 2026)
        types = {f["type"] for f in r["findings"]}
        self.assertTrue({"brute_force", "password_spraying", "success_after_bruteforce",
                         "post_compromise_activity", "privilege_change", "account_created"} <= types)
        self.assertEqual(r["risk"], "Critical")
        self.assertEqual(r["stats"]["by_type"]["login_failed"], 31)
        self.assertEqual(r["failed_by_ip"][0], {"ip": "203.0.113.45", "count": 30})

    def test_windows_csv(self):
        r = analyze_log(CSV, "security.csv")
        types = {f["type"] for f in r["findings"]}
        self.assertIn("brute_force", types)
        self.assertIn("success_after_bruteforce", types)
        self.assertIn("log_cleared", types)

    def test_below_threshold_is_quiet(self):
        text = b"Oct 12 12:00:00 h sshd[1]: Failed password for bob from 198.51.100.1 port 1 ssh2\n"
        r = analyze_log(text, "auth.log", 2026)
        self.assertFalse([f for f in r["findings"] if f["type"] == "brute_force"])

    def test_unparsable_log(self):
        r = analyze_log(b"nothing useful here", "x.log", 2026)
        self.assertEqual(r["stats"]["events"], 0)


if __name__ == "__main__":
    unittest.main()
