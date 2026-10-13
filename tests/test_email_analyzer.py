import unittest
from pathlib import Path

from modules.email_analyzer import analyze_eml

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "phishing_sample.eml"

BENIGN = b"""From: Bob <bob@acme-corp.example>
To: alice@acme-corp.example
Subject: Lunch?
Date: Mon, 12 Oct 2026 10:00:00 +0000
Message-ID: <1@acme-corp.example>
Authentication-Results: mx.acme-corp.example; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Fancy lunch at noon? https://acme-corp.example/menu
"""


class EmailTests(unittest.TestCase):
    def test_phishing_sample_is_high_risk(self):
        r = analyze_eml(SAMPLE.read_bytes())
        self.assertEqual(r["risk"], "High")
        self.assertEqual(r["authentication"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        self.assertEqual(r["origin_ip"], "203.0.113.45")
        findings = " | ".join(i["finding"] for i in r["indicators"])
        for expected in ("SPF check failed", "DMARC check failed", "Reply-To domain differs", "brand impersonation",
                         "raw IP address", "Deceptive link", "attachment"):
            self.assertIn(expected, findings)
        self.assertEqual(r["attachments"][0]["risk"], "High")
        self.assertIn("203.0.113.45", r["iocs"]["ips"])

    def test_benign_email_is_info(self):
        r = analyze_eml(BENIGN)
        self.assertEqual(r["risk"], "Info")
        self.assertEqual(r["indicators"], [])

    def test_garbage_input_does_not_crash(self):
        r = analyze_eml(b"\x00\x01 not an email")
        self.assertIn("risk", r)


if __name__ == "__main__":
    unittest.main()
