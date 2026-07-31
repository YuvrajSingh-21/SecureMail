import unittest
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.services.entropy import EntropyEngine

class TestEntropyEngine(unittest.TestCase):
    def test_shannon_entropy(self):
        engine = EntropyEngine()
        self.assertEqual(engine.calculate_shannon_entropy(b""), 0.0)
        self.assertEqual(engine.calculate_shannon_entropy(b"AAAA"), 0.0)
        self.assertTrue(engine.calculate_shannon_entropy(b"\x00\x01\x02\x03") > 1.0)
        
    def test_run(self):
        ctx = AnalysisContext(analysis_id="1", file_path="", declared_filename="", declared_mime_type="")
        engine = EntropyEngine()
        engine.run(b"test data", ctx)
        self.assertIn("entropy_profile", ctx.metadata)
        self.assertIn("whole_file", ctx.metadata["entropy_profile"])
        self.assertIn("entropy", ctx.completed_stages)

if __name__ == "__main__":
    unittest.main()
