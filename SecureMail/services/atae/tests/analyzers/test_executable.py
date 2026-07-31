import unittest
import struct
from SecureMail.services.atae.analyzers.executable import ExecutableAnalyzer
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.enums import Severity
from SecureMail.services.atae.core.exceptions import ATAEParserError

class TestExecutableAnalyzer(unittest.TestCase):
    def test_invalid_header(self):
        data = b"NOT AN EXE"
        ctx = AnalysisContext("job1", "", "test.exe", "application/x-dosexec")
        analyzer = ExecutableAnalyzer()
        with self.assertRaises(ATAEParserError):
            analyzer.analyze(data, ctx)
            
    def test_pe_invalid_lfanew(self):
        data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFFFF)
        ctx = AnalysisContext("job2", "", "test.exe", "application/x-dosexec")
        analyzer = ExecutableAnalyzer()
        findings = analyzer.analyze(data, ctx)
    def test_pe_valid_with_debug(self):
        from unittest.mock import patch
        from SecureMail.services.atae.analyzers.executable import ExecutableParserResult
        with patch('SecureMail.services.atae.analyzers.executable.PEParser.parse') as mock_parse:
            mock_parse.return_value = ExecutableParserResult(format_name="PE", has_debug=True, is_valid=True)
            data = b"MZ\x00\x00"
            ctx = AnalysisContext("job3", "", "test.exe", "application/x-dosexec")
            analyzer = ExecutableAnalyzer()
            findings = analyzer.analyze(data, ctx)
            techs = [f.technique_id for f in findings]
            self.assertNotIn("EXEC_INVALID_HEADER", techs)
            self.assertIn("EXEC_DEBUG_INFO", techs)

    def test_pe_suspicious_import(self):
        from unittest.mock import patch
        from SecureMail.services.atae.analyzers.executable import ExecutableParserResult, ExecutableImport
        with patch('SecureMail.services.atae.analyzers.executable.PEParser.parse') as mock_parse:
            mock_parse.return_value = ExecutableParserResult(
                format_name="PE", 
                is_valid=True,
                imports=[ExecutableImport("kernel32.dll", "VirtualProtect")]
            )
            data = b"MZ\x00\x00"
            ctx = AnalysisContext("job4", "", "test.exe", "application/x-dosexec")
            analyzer = ExecutableAnalyzer()
            findings = analyzer.analyze(data, ctx)
            techs = [f.technique_id for f in findings]
            self.assertIn("EXEC_SUSPICIOUS_IMPORT", techs)
        
    def test_pe_packed_upx(self):
        from unittest.mock import patch
        from SecureMail.services.atae.analyzers.executable import ExecutableParserResult, ExecutableSection
        with patch('SecureMail.services.atae.analyzers.executable.PEParser.parse') as mock_parse:
            mock_parse.return_value = ExecutableParserResult(
                format_name="PE",
                is_valid=True,
                sections=[ExecutableSection(".upx0", 1000, 7.8, True, True, b"")]
            )
            data = b"MZ\x00\x00"
            ctx = AnalysisContext("job5", "", "test.exe", "application/x-dosexec")
            analyzer = ExecutableAnalyzer()
            findings = analyzer.analyze(data, ctx)
            techs = [f.technique_id for f in findings]
            self.assertIn("EXEC_SUSPICIOUS_SECTION", techs)
            self.assertIn("EXEC_HIGH_ENTROPY_SECTION", techs)
            self.assertIn("EXEC_RWX_SECTION", techs)
            self.assertIn("EXEC_PACKED", techs)
        
    def test_elf_suspicious_import(self):
        data = b"\x7fELF" + b"\x00" * 100 + b"ptrace"
        ctx = AnalysisContext("job6", "", "test.elf", "application/x-elf")
        analyzer = ExecutableAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("EXEC_SUSPICIOUS_IMPORT", techs)

    def test_macho_valid(self):
        data = b"\xfe\xed\xfa\xce" + b"\x00" * 100
        ctx = AnalysisContext("job7", "", "test.macho", "application/x-mach-o")
        analyzer = ExecutableAnalyzer()
        findings = analyzer.analyze(data, ctx)
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
