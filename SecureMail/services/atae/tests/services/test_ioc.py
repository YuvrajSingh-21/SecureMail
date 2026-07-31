import unittest
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.services.ioc import IOCExtractor

class TestIOCExtractor(unittest.TestCase):
    def test_extract_ipv4(self):
        extractor = IOCExtractor()
        data = b"Connect to 192.168.1.1 or 8.8.8.8"
        iocs = extractor.extract_iocs(data)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], "8.8.8.8")
        
    def test_extract_md5(self):
        extractor = IOCExtractor()
        data = b"Hash: 619e987db5194d1c6456b322e2039db6"
        iocs = extractor.extract_iocs(data)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], "619e987db5194d1c6456b322e2039db6")

    def test_run(self):
        ctx = AnalysisContext(analysis_id="1", file_path="", declared_filename="", declared_mime_type="")
        extractor = IOCExtractor()
        extractor.run(b"Contact 1.1.1.1", ctx)
        self.assertEqual(len(ctx.iocs), 1)
        self.assertIn("ioc_extraction", ctx.completed_stages)

if __name__ == "__main__":
    unittest.main()
