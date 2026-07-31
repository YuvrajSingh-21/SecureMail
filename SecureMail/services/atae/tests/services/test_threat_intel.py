import unittest
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.enums import Severity
from SecureMail.services.atae.services.threat_intel import ThreatIntelligenceClient, MockThreatIntelProvider

class TestThreatIntel(unittest.TestCase):
    def test_run_known_malicious(self):
        ctx = AnalysisContext(analysis_id="1", file_path="", declared_filename="", declared_mime_type="")
        ctx.hashes["sha256"] = "bad_hash"
        
        client = ThreatIntelligenceClient(MockThreatIntelProvider())
        client.run(ctx)
        
        self.assertEqual(len(ctx.findings), 1)
        self.assertEqual(ctx.findings[0].technique_id, "TI_KNOWN_MALICIOUS")
        self.assertEqual(ctx.findings[0].severity, Severity.CRITICAL)
        self.assertTrue(ctx.metadata["threat_intel"]["malicious"])
        self.assertIn("threat_intel", ctx.completed_stages)
        
    def test_run_missing_hash(self):
        ctx = AnalysisContext(analysis_id="2", file_path="", declared_filename="", declared_mime_type="")
        client = ThreatIntelligenceClient(MockThreatIntelProvider())
        client.run(ctx)
        
        self.assertEqual(len(ctx.findings), 0)
        self.assertIn("threat_intel", ctx.incomplete_stages)

if __name__ == "__main__":
    unittest.main()
