import unittest
import io
import zipfile
from SecureMail.services.atae.analyzers.office import OfficeAnalyzer
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.enums import Severity
from SecureMail.services.atae.core.exceptions import ATAEParserError

class TestOfficeAnalyzer(unittest.TestCase):
    def _create_zip(self, files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_invalid_header(self):
        data = b"NOT AN OFFICE FILE"
        ctx = AnalysisContext("job1", "", "test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        analyzer = OfficeAnalyzer()
        with self.assertRaises(ATAEParserError):
            analyzer.analyze(data, ctx)

    def test_ooxml_safe(self):
        data = self._create_zip({"[Content_Types].xml": b"<?xml version=\"1.0\"?>"})
        ctx = AnalysisContext("job2", "", "test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        self.assertEqual(len(findings), 0)

    def test_ooxml_vba_macro(self):
        data = self._create_zip({"word/vbaProject.bin": b"VBA MACRO"})
        ctx = AnalysisContext("job3", "", "test.docm", "application/vnd.ms-word.document.macroEnabled.12")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("OFFICE_VBA_MACROS", techs)

    def test_ooxml_external_template(self):
        rels_data = b'<?xml version="1.0"?><Relationships><Relationship Type="attachedTemplate" TargetMode="External" Target="http://malicious.com/template.dotm"/></Relationships>'
        data = self._create_zip({"word/_rels/settings.xml.rels": rels_data})
        ctx = AnalysisContext("job4", "", "test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("OFFICE_EXTERNAL_TEMPLATE", techs)

    def test_ooxml_hidden_sheet(self):
        wb_data = b'<?xml version="1.0"?><workbook><sheets><sheet state="veryHidden"/></sheets></workbook>'
        data = self._create_zip({"xl/workbook.xml": wb_data})
        ctx = AnalysisContext("job5", "", "test.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("OFFICE_HIDDEN_SHEET", techs)

    def test_ooxml_embedded_executable(self):
        data = self._create_zip({"word/embeddings/oleObject1.bin": b"MZ...\x00\x00PE\x00\x00"})
        ctx = AnalysisContext("job6", "", "test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("OFFICE_EMBEDDED_EXECUTABLE", techs)

    def test_ole2_macros_and_autoexec(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b" \x00 " * 10 + b"_VBA_PROJECT AutoOpen"
        ctx = AnalysisContext("job7", "", "test.doc", "application/msword")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("OFFICE_VBA_MACROS", techs)
        self.assertIn("OFFICE_AUTO_EXEC", techs)

    def test_ole2_encrypted(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b" DataSpaces EncryptedPackage"
        ctx = AnalysisContext("job8", "", "test.doc", "application/msword")
        analyzer = OfficeAnalyzer()
        findings = analyzer.analyze(data, ctx)
        techs = [f.technique_id for f in findings]
        self.assertIn("OFFICE_ENCRYPTED", techs)

if __name__ == "__main__":
    unittest.main()
