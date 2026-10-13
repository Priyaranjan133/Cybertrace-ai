import tempfile
import unittest
from pathlib import Path

from database import db_manager as db
from modules import correlation_engine, demo, pipeline, report_generator


class DbTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self._orig = (db.DATA_DIR, db.EVIDENCE_DIR, db.DB_PATH)
        db.DATA_DIR, db.EVIDENCE_DIR, db.DB_PATH = root, root / "evidence", root / "t.db"
        db.init_db()

    def tearDown(self):
        db.DATA_DIR, db.EVIDENCE_DIR, db.DB_PATH = self._orig
        self._tmp.cleanup()

    def test_case_ids_increment(self):
        a, b = db.create_case("A", "me"), db.create_case("B", "me")
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("CASE-"))

    def test_tampering_with_stored_evidence_is_detected(self):
        cid = db.create_case("T", "me")
        eid = db.add_evidence(cid, "note.txt", b"original", "File", "me")
        self.assertEqual(db.read_evidence_bytes(eid), b"original")
        path = db.DATA_DIR / db.get_evidence(eid)["stored_path"]
        path.chmod(0o644)
        path.write_bytes(b"tampered")
        with self.assertRaises(db.IntegrityError):
            db.read_evidence_bytes(eid)
        rep = db.verify_all(cid)
        self.assertEqual(rep[0]["status"], "HASH MISMATCH")
        self.assertEqual(db.stats()["verified_pct"], 0)

    def test_audit_chain_detects_edits(self):
        cid = db.create_case("T", "me")
        db.add_evidence(cid, "a.txt", b"x", "File", "me")
        ok, bad, n = db.verify_audit_chain()
        self.assertTrue(ok)
        self.assertGreaterEqual(n, 2)
        with db.connect() as c:
            c.execute("UPDATE audit_log SET actor='mallory' WHERE id=1")
        ok, bad, _ = db.verify_audit_chain()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_filename_is_sanitised(self):
        cid = db.create_case("T", "me")
        eid = db.add_evidence(cid, "../../etc/passwd", b"x", "File", "me")
        stored = db.get_evidence(eid)["stored_path"]
        self.assertNotIn("..", stored)
        self.assertTrue((db.DATA_DIR / stored).resolve().is_relative_to(db.EVIDENCE_DIR.resolve()))

    def test_demo_case_correlates_and_reports(self):
        cid = demo.load_demo("tester")
        self.assertEqual(demo.load_demo("tester"), cid)  # idempotent
        evidence = db.list_evidence(cid)
        results = db.get_results(cid)
        self.assertEqual(len(results), 2)
        corr = correlation_engine.correlate(results, {e["id"]: e for e in evidence})
        self.assertTrue(any(c["value"] == "203.0.113.45" for c in corr))
        pdf = report_generator.build_pdf(db.get_case(cid), evidence, results, corr, db.get_audit(cid), "Summary text")
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 3000)
        self.assertIn(b"sha256", report_generator.evidence_csv(evidence).lower() + b"sha256")
        self.assertIn(b"severity", report_generator.findings_csv(results, evidence))


if __name__ == "__main__":
    unittest.main()
