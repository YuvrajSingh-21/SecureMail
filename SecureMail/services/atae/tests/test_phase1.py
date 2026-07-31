import unittest
import os
import threading
from SecureMail.services.atae.core.enums import Severity, Confidence, VerdictBand
from SecureMail.services.atae.core.models import Finding, AttachmentVerdict, ForensicRecord
from SecureMail.services.atae.core.context import AnalysisContext
from SecureMail.services.atae.core.exceptions import ATAEResourceExhaustionError, ATAEError
from SecureMail.services.atae.core.registry import AnalyzerRegistry
from SecureMail.services.atae.core.interfaces import BaseAnalyzer
from SecureMail.services.atae.core.config import ATAEConfig
from SecureMail.services.atae.core.logger import get_contextual_logger
from SecureMail.services.atae.triage.workspace import TemporaryWorkspaceManager
from SecureMail.services.atae.triage.hashing import HashingService
from SecureMail.services.atae.triage.magic import MagicByteDetection, FallbackMagicProvider
from SecureMail.services.atae.triage.router import AttachmentRouter

class DummyAnalyzer(BaseAnalyzer):
    def analyze(self, file_bytes: bytes, context: AnalysisContext):
        return []

class TestATAEPhase1(unittest.TestCase):
    def test_enums(self):
        f = Finding(
            technique_id="T1001",
            severity=Severity.HIGH,
            description="Test finding",
            evidence_locator="offset:100",
            confidence=Confidence.HIGH
        )
        self.assertEqual(f.severity, Severity.HIGH)

    def test_hashing_service(self):
        data = b"Hello ATAE"
        hashes = HashingService.compute_hashes(data)
        self.assertEqual(hashes["md5"], "619e987db5194d1c6456b322e2039db6")

    def test_workspace_manager(self):
        wm = TemporaryWorkspaceManager(base_dir="/tmp/atae_test_workspace")
        path = wm.create_workspace("test-job-123")
        self.assertTrue(os.path.exists(path))
        
        test_file = os.path.join(path, "test.txt")
        with open(test_file, "wb") as f:
            f.write(b"sensitive data")
            
        wm.secure_wipe(path)
        self.assertFalse(os.path.exists(path))

    def test_analysis_context_limits(self):
        ctx = AnalysisContext(
            analysis_id="job1",
            file_path="dummy.pdf",
            declared_filename="dummy.pdf",
            declared_mime_type="application/pdf"
        )
        ctx.check_limits(added_size=1024)
        
        with self.assertRaises(ATAEResourceExhaustionError):
            ctx.check_limits(added_size=1000 * 1024 * 1024)

    def test_analysis_context_tracking(self):
        ctx = AnalysisContext(
            analysis_id="job2",
            file_path="test.exe",
            declared_filename="test.exe",
            declared_mime_type="application/x-dosexec"
        )
        ctx.mark_stage_complete("hashing")
        ctx.mark_stage_incomplete("pdf_analysis")
        self.assertIn("hashing", ctx.completed_stages)
        self.assertIn("pdf_analysis", ctx.incomplete_stages)

    def test_magic_byte_detection(self):
        detector = MagicByteDetection(FallbackMagicProvider())
        mime, name = detector.identify(b"%PDF-1.4...")
        self.assertEqual(mime, "application/pdf")
        
        mime, name = detector.identify(b"\x50\x4B\x03\x04...")
        self.assertEqual(mime, "application/zip")

    def test_fake_extension(self):
        is_fake = MagicByteDetection.detect_fake_extension("application/zip", "invoice.pdf")
        self.assertTrue(is_fake)
        is_fake = MagicByteDetection.detect_fake_extension("application/pdf", "invoice.pdf")
        self.assertFalse(is_fake)

    def test_registry_thread_safety(self):
        AnalyzerRegistry.clear()
        
        def register_task(name):
            AnalyzerRegistry.register(name, DummyAnalyzer)
            
        threads = [threading.Thread(target=register_task, args=(f"type_{i}",)) for i in range(100)]
        for t in threads: t.start()
        for t in threads: t.join()
        
        self.assertEqual(len(AnalyzerRegistry._registry), 100)

    def test_router_configurable(self):
        AnalyzerRegistry.clear()
        AnalyzerRegistry.register("custom_pdf", DummyAnalyzer)
        
        custom_mapping = {"application/pdf": "custom_pdf"}
        router = AttachmentRouter(routing_map=custom_mapping)
        self.assertEqual(router.route("application/pdf"), DummyAnalyzer)
        
    def test_config_validation(self):
        with self.assertRaises(ValueError):
            ATAEConfig(max_nesting_depth=0)

    def test_contextual_logger(self):
        logger = get_contextual_logger("test_logger", "job-999")
        self.assertEqual(logger.extra["analysis_id"], "job-999")

if __name__ == "__main__":
    unittest.main()
