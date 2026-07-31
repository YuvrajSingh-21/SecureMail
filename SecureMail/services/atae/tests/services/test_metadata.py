import unittest
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.services.metadata import MetadataExtractor

class TestMetadataExtractor(unittest.TestCase):
    def test_extract(self):
        extractor = MetadataExtractor()
        meta = extractor.extract(b"1234567890")
        self.assertEqual(meta["size_bytes"], 10)
        self.assertEqual(meta["starts_with_hex"], b"12345678".hex())
        
    def test_run(self):
        ctx = AnalysisContext(analysis_id="1", file_path="", declared_filename="", declared_mime_type="")
        extractor = MetadataExtractor()
        extractor.run(b"data", ctx)
        self.assertIn("basic_file_metadata", ctx.metadata)
        self.assertIn("metadata_extraction", ctx.completed_stages)

if __name__ == "__main__":
    unittest.main()
