import io
import unittest
import zipfile

from modules.file_analyzer import analyze_file


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def _levels(res):
    return {i["severity"] for i in res["indicators"]}


class FileTests(unittest.TestCase):
    def test_hashes_are_correct(self):
        r = analyze_file("a.txt", b"hello")
        self.assertEqual(r["hashes"]["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    def test_clean_text_is_info(self):
        r = analyze_file("notes.txt", b"just some notes\n")
        self.assertEqual(r["risk"], "Info")
        self.assertTrue(r["extension_matches"])

    def test_pe_disguised_as_pdf_is_high(self):  # executable posing as a document
        r = analyze_file("report.pdf", b"MZ" + b"\x00" * 200)
        self.assertEqual(r["risk"], "High")
        self.assertIn("High", _levels(r))
        self.assertFalse(r["extension_matches"])

    def test_double_extension_is_high(self):
        r = analyze_file("Invoice.pdf.exe", b"MZ" + b"\x00" * 200)
        self.assertEqual(r["risk"], "High")

    def test_rtlo_detected(self):
        r = analyze_file("invoice\u202egpj.exe", b"MZ\x00\x00")
        self.assertTrue(any("override" in i["finding"] for i in r["indicators"]))

    def test_zip_with_executable_and_no_extraction(self):
        r = analyze_file("pack.zip", _zip({"readme.txt": "x", "payload.exe": "MZ"}))
        self.assertEqual(r["archive"]["total_entries"], 2)
        self.assertTrue(any("inside archive" in i["finding"] for i in r["indicators"]))

    def test_office_macro_flagged_and_metadata_read(self):
        core = '<cp:coreProperties><dc:creator>Eve</dc:creator></cp:coreProperties>'
        r = analyze_file("q3.docm", _zip({"docProps/core.xml": core, "word/vbaProject.bin": b"x"}))
        self.assertEqual(r["metadata"].get("Author"), "Eve")
        self.assertTrue(any("macro" in i["finding"].lower() for i in r["indicators"]))

    def test_pdf_javascript_flagged(self):
        r = analyze_file("a.pdf", b"%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")
        self.assertTrue(any("JavaScript" in i["finding"] for i in r["indicators"]))


if __name__ == "__main__":
    unittest.main()
