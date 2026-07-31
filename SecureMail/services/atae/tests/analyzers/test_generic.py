import unittest
import base64
from SecureMail.services.atae.analyzers.generic import GenericAnalyzer
from SecureMail.services.atae.core.context import AnalysisContext

class TestGenericAnalyzer(unittest.TestCase):
    def test_unknown_binary(self):
        data = b'\x01\x02\x03\x04\x05' * 100
        ctx = AnalysisContext("gen1", "", "test.dat", "application/octet-stream")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_UNKNOWN_BINARY", techs)

    def test_double_extension(self):
        data = b'Hello world'
        ctx = AnalysisContext("gen2", "", "malware.pdf.exe", "application/x-dosexec")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_DOUBLE_EXTENSION", techs)

    def test_extension_mismatch(self):
        data = b'MZ\x90\x00\x03\x00' + b'\x00'*100 # PE signature
        ctx = AnalysisContext("gen3", "", "document.pdf", "application/pdf")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_EXTENSION_MISMATCH", techs)
        
    def test_null_byte_filename(self):
        data = b'Hello'
        ctx = AnalysisContext("gen4", "", "test.txt\x00.exe", "text/plain")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_NULL_BYTE_FILENAME", techs)

    def test_embedded_executable(self):
        data = b'Some random text data ' + b'MZ\x90\x00\x03\x00' + b'\x00'*100
        ctx = AnalysisContext("gen5", "", "test.txt", "text/plain")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_EMBEDDED_OBJECT", techs)

    def test_embedded_archive(self):
        data = b'Appended to log file ' + b'PK\x03\x04' + b'\x00'*50
        ctx = AnalysisContext("gen6", "", "test.log", "text/plain")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_EMBEDDED_OBJECT", techs)
        
    def test_encoded_blob(self):
        mz = b'MZ\x90\x00\x03\x00' + b'\x00'*100
        b64 = base64.b64encode(mz)
        data = b'Here is some text ' + b64
        ctx = AnalysisContext("gen7", "", "test.txt", "text/plain")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_ENCODED_BLOB", techs)
        self.assertIn("GENERIC_ENCODED_EXECUTABLE", techs)

    def test_large_string_regions(self):
        data = b'\x00' * 300 + b'A' * 150 + b'\x00\x01' + b'B' * 120 + b'\x00\x01' + b'C' * 110 + b'\x00' + b'D'*105 + b'\x00' + b'E'*101 + b'\x00' + b'F'*111 + b'\x00'
        ctx = AnalysisContext("gen8", "", "test.bin", "application/octet-stream")
        analyzer = GenericAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("GENERIC_MIXED_CONTENT", techs)

if __name__ == "__main__":
    unittest.main()
