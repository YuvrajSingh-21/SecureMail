import unittest
import struct
from SecureMail.services.atae.integration.orchestrator import ATAEEngine, AnalyzerSelector
from SecureMail.services.atae.integration.bootstrap import register_all_analyzers
from SecureMail.services.atae.triage.magic import MagicByteDetection, FallbackMagicProvider

class TestATAEIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        register_all_analyzers()
        cls.engine = ATAEEngine()

    def test_pipeline_pdf(self):
        data = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Outlines 2 0 R /Pages 3 0 R >>\nendobj\n'
        report = self.engine.analyze_attachment("int-1", data, "test.pdf", "application/pdf")
        self.assertEqual(report.analyzer_used, "PDFAnalyzer")

    def test_pipeline_pe(self):
        data = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00' + b'\x00' * 41
        data += struct.pack('<I', 0x40) # e_lfanew
        data += b'PE\x00\x00' # PE header
        data += b'\x00'*100
        report = self.engine.analyze_attachment("int-2", data, "malware.exe", "application/x-dosexec")
        self.assertEqual(report.analyzer_used, "ExecutableAnalyzer")

    def test_pipeline_fallback_generic(self):
        data = b'\x01\x02\x03\x04\x05' * 100
        report = self.engine.analyze_attachment("int-3", data, "unknown.dat", "application/octet-stream")
        self.assertEqual(report.analyzer_used, "GenericAnalyzer")
        techs = [f.technique_id for f in report.findings]
        self.assertIn("GENERIC_UNKNOWN_BINARY", techs)

    def test_pipeline_selector_priority(self):
        # A file with .zip extension but %PDF- magic
        data = b'%PDF-1.4\n\n'
        report = self.engine.analyze_attachment("int-4", data, "fake.zip", "application/zip")
        self.assertEqual(report.analyzer_used, "PDFAnalyzer")

    def test_pipeline_selector_extension_last(self):
        # A file with octet-stream magic, but .js extension
        data = b'function() { eval("hello"); }'
        report = self.engine.analyze_attachment("int-5", data, "script.js", "application/octet-stream")
        self.assertEqual(report.analyzer_used, "ScriptAnalyzer")

    def test_pipeline_correlation(self):
        # Embedded ZIP + PE in GenericAnalyzer
        data = b'\x01\x02\x03\x04' + b'MZ\x90\x00\x03\x00' + b'\x00'*50 + b'PK\x03\x04' + b'\x00'*50
        report = self.engine.analyze_attachment("int-6", data, "unknown.dat", "application/octet-stream")
        self.assertEqual(report.analyzer_used, "GenericAnalyzer")
        techs = [f.technique_id for f in report.findings]
        self.assertIn("CORRELATED_EMBEDDED_ZIP_PE", techs)

if __name__ == "__main__":
    unittest.main()
