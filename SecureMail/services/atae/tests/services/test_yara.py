import unittest
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.enums import Severity
from SecureMail.services.atae.core.models import YaraMatch
from SecureMail.services.atae.services.yara_engine import YaraEngine, MockYaraProvider

class TestYaraEngine(unittest.TestCase):
    def test_run_match(self):
        ctx = AnalysisContext(analysis_id="1", file_path="", declared_filename="", declared_mime_type="")
        engine = YaraEngine(MockYaraProvider())
        engine.run(b"Some MALICIOUS_STRING here", ctx)
        
        self.assertEqual(len(ctx.findings), 1)
        finding = ctx.findings[0]
        self.assertEqual(finding.technique_id, "YARA_Detect_Malicious_String")
        self.assertEqual(finding.severity, Severity.HIGH)
        
        self.assertIn("yara_matches", ctx.metadata)
        self.assertIn("yara_scan", ctx.completed_stages)

    def test_run_no_match(self):
        ctx = AnalysisContext(analysis_id="2", file_path="", declared_filename="", declared_mime_type="")
        engine = YaraEngine(MockYaraProvider())
        engine.run(b"Clean file", ctx)
        self.assertEqual(len(ctx.findings), 0)

if __name__ == "__main__":
    unittest.main()
