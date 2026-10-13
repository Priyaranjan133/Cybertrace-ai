import unittest

from modules.ioc_extractor import extract_iocs, is_public_ip


class IocTests(unittest.TestCase):
    def test_extracts_each_kind(self):
        text = ("Visit hxxp://evil[.]example/login and http://203.0.113.9/a.php, mail bad.guy@phish.example, "
                "hash d41d8cd98f00b204e9800998ecf8427e. Contact 198.51.100.4.")
        r = extract_iocs(text)
        self.assertIn("http://evil.example/login", r["urls"])
        self.assertIn("203.0.113.9", r["ips"])
        self.assertIn("198.51.100.4", r["ips"])
        self.assertIn("evil.example", r["domains"])
        self.assertIn("phish.example", r["domains"])
        self.assertIn("bad.guy@phish.example", r["emails"])
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", r["hashes"])

    def test_filenames_and_bad_ips_are_not_iocs(self):
        r = extract_iocs("see setup.exe and config.json, version 999.1.1.1")
        self.assertEqual(r["domains"], [])
        self.assertEqual(r["ips"], [])

    def test_local_part_not_reported_as_domain(self):
        r = extract_iocs("john.smith@corp.example")
        self.assertEqual(r["domains"], ["corp.example"])

    def test_public_ip(self):
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertFalse(is_public_ip("10.0.0.5"))
        self.assertFalse(is_public_ip("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
