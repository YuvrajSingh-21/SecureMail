import unittest
import zlib
from unittest.mock import patch
from SecureMail.services.atae.analyzers.pdf import PDFAnalyzer
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.enums import Severity
from SecureMail.services.atae.core.exceptions import ATAEParserError

class TestPDFAnalyzer(unittest.TestCase):
    def test_invalid_header(self):
        data = b"NOT A PDF"
        ctx = AnalysisContext("job1", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        with self.assertRaises(ATAEParserError):
            analyzer.analyze(data, ctx)

    def test_safe_pdf(self):
        data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        ctx = AnalysisContext("job2", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        findings = analyzer.analyze(data, ctx)
        self.assertEqual(len(findings), 0)
        self.assertIn("pdf_analysis", ctx.completed_stages)

    def test_javascript_and_openaction(self):
        data = b"%PDF-1.4\n<< /OpenAction /JS /JavaScript (app.alert(1);) >>\n%%EOF"
        ctx = AnalysisContext("job3", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        techs = [f.technique_id for f in findings]
        self.assertIn("PDF_JAVASCRIPT", techs)
        self.assertIn("PDF_OPENACTION", techs)

    def test_malformed_no_eof(self):
        data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj"
        ctx = AnalysisContext("job4", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        techs = [f.technique_id for f in findings]
        self.assertIn("PDF_MALFORMED", techs)

    def test_incremental_updates(self):
        data = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n2 0 obj\n<<>>\nendobj\n%%EOF"
        ctx = AnalysisContext("job5", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        techs = [f.technique_id for f in findings]
        self.assertIn("PDF_INCREMENTAL_UPDATES", techs)

    def test_embedded_executable(self):
        mz_payload = zlib.compress(b"MZ...\x00\x00PE\x00\x00")
        data = b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + mz_payload + b"\nendstream\n%%EOF"
        ctx = AnalysisContext("job6", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        techs = [f.technique_id for f in findings]
        self.assertIn("PDF_EMBEDDED_EXECUTABLE", techs)

    def test_suspicious_producer(self):
        data = b"%PDF-1.4\n<< /Producer (Ghostscript 9.50) >>\n%%EOF"
        ctx = AnalysisContext("job7", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        techs = [f.technique_id for f in findings]
        self.assertIn("PDF_SUSPICIOUS_PRODUCER", techs)

    def test_ioc_and_entropy_reuse(self):
        payload = b"<< /Filter /FlateDecode >>\nstream\n" + zlib.compress(b"Contact 192.168.1.1 or 8.8.8.8") + b"\nendstream"
        data = b"%PDF-1.4\n" + payload + b"\n%%EOF"
        ctx = AnalysisContext("job8", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        analyzer.analyze(data, ctx)
        
        iocs = [ioc["value"] for ioc in ctx.iocs]
        self.assertIn("8.8.8.8", iocs)
        self.assertIn("pdf_stream_0", ctx.metadata.get("entropy_profile", {}))
        self.assertIn("pdf_metadata", ctx.metadata)

    def test_excessive_objects(self):
        data = b"%PDF-1.4\n" + b"1 0 obj\n" * 15 + b"%%EOF"
        ctx = AnalysisContext("job9", "", "test.pdf", "application/pdf")
        analyzer = PDFAnalyzer()
        
        with patch('SecureMail.services.atae.analyzers.pdf.config') as mock_config:
            mock_config.max_pdf_objects = 10
            findings = analyzer.analyze(data, ctx)
            
        techs = [f.technique_id for f in findings]
        self.assertIn("PDF_EXCESSIVE_OBJECTS", techs)

if __name__ == "__main__":
    unittest.main()
