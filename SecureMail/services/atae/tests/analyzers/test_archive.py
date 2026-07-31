import unittest
import os
import io
import zipfile
import tarfile
import stat
from unittest.mock import patch
from SecureMail.services.atae.analyzers.archive import ArchiveAnalyzer, ZipArchiveHandler, TarArchiveHandler
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.enums import Severity
from SecureMail.services.atae.core.config import config
from SecureMail.services.atae.triage.workspace import TemporaryWorkspaceManager

class TestArchiveAnalyzer(unittest.TestCase):
    def setUp(self):
        self.wm = TemporaryWorkspaceManager("/tmp/atae_test_archive")
        self.workspace = self.wm.create_workspace("test_job")
        
    def tearDown(self):
        self.wm.secure_wipe(self.workspace)

    def _create_zip(self, files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def _create_tar(self, files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, content in files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    def test_safe_zip(self):
        data = self._create_zip({"test.txt": b"Hello"})
        ctx = AnalysisContext("job1", "", "test.zip", "application/zip", workspace_path=self.workspace)
        analyzer = ArchiveAnalyzer()
        findings = analyzer.analyze(data, ctx)
        self.assertEqual(len(findings), 0)

    def test_suspicious_extension(self):
        data = self._create_zip({"payload.exe": b"MZ..."})
        ctx = AnalysisContext("job2", "", "test.zip", "application/zip", workspace_path=self.workspace)
        analyzer = ArchiveAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        has_suspicious = any(f.technique_id == "ARCHIVE_SUSPICIOUS_CONTENT" for f in findings)
        has_magic = any(f.technique_id == "ARCHIVE_MAGIC_EXECUTABLE" for f in findings)
        self.assertTrue(has_suspicious or has_magic)

    def test_zip_slip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../etc/passwd", b"root:x:0:0")
        data = buf.getvalue()
        
        ctx = AnalysisContext("job3", "", "test.zip", "application/zip", workspace_path=self.workspace)
        analyzer = ArchiveAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        slip_finding = next((f for f in findings if f.technique_id == "ARCHIVE_PATH_TRAVERSAL"), None)
        self.assertIsNotNone(slip_finding)
        self.assertEqual(slip_finding.severity, Severity.CRITICAL)

    def test_hidden_file(self):
        data = self._create_zip({".hidden.sh": b"echo pwnd"})
        ctx = AnalysisContext("job4", "", "test.zip", "application/zip", workspace_path=self.workspace)
        analyzer = ArchiveAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        hidden = next((f for f in findings if f.technique_id == "ARCHIVE_HIDDEN_FILE"), None)
        self.assertIsNotNone(hidden)

    def test_archive_bomb_ratio(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("huge.txt", b"\x00" * (1024 * 1024))
            
        data = buf.getvalue()
        ctx = AnalysisContext("job5", "", "bomb.zip", "application/zip", workspace_path=self.workspace)
        analyzer = ArchiveAnalyzer()
        
        with patch('SecureMail.services.atae.analyzers.archive.config') as mock_config:
            mock_config.max_compression_ratio = 2
            mock_config.max_nesting_depth = 5
            mock_config.max_decompressed_size_mb = 500
            findings = analyzer.analyze(data, ctx)
        
        bomb = next((f for f in findings if f.technique_id in ("ARCHIVE_BOMB_RATIO", "ARCHIVE_MEMBER_BOMB_RATIO")), None)
        self.assertIsNotNone(bomb)
        self.assertEqual(bomb.severity, Severity.CRITICAL)

    def test_excessive_nesting(self):
        data = self._create_zip({"test.txt": b"Hello"})
        ctx = AnalysisContext("job6", "", "test.zip", "application/zip", workspace_path=self.workspace)
        ctx.current_depth = config.max_nesting_depth + 1
        analyzer = ArchiveAnalyzer()
        findings = analyzer.analyze(data, ctx)
        
        nesting = next((f for f in findings if f.technique_id == "ARCHIVE_EXCESSIVE_NESTING"), None)
        self.assertIsNotNone(nesting)

    def test_tar_safe(self):
        data = self._create_tar({"script.js": b"alert(1);"})
        ctx = AnalysisContext("job7", "", "test.tar", "application/x-tar", workspace_path=self.workspace)
        analyzer = ArchiveAnalyzer()
        findings = analyzer.analyze(data, ctx)
        suspicious = next((f for f in findings if f.technique_id == "ARCHIVE_SUSPICIOUS_CONTENT"), None)
        self.assertIsNotNone(suspicious)

if __name__ == "__main__":
    unittest.main()
