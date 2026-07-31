import unittest
from SecureMail.services.atae.core.models import Finding
from SecureMail.services.atae.core.enums import Severity, Confidence, VerdictBand
from SecureMail.services.atae.services.risk import RiskScoringEngine

class TestRiskScoring(unittest.TestCase):
    def test_compute_score(self):
        engine = RiskScoringEngine()
        f1 = Finding("T1", Severity.HIGH, "test", "file", Confidence.HIGH)
        # 45 * 1.2 = 54
        score = engine.compute_score([f1])
        self.assertEqual(score, 54)
        
    def test_suppressed_finding(self):
        engine = RiskScoringEngine()
        f1 = Finding("T1", Severity.HIGH, "test", "file", Confidence.HIGH, suppressed=True)
        score = engine.compute_score([f1])
        self.assertEqual(score, 0)
        
    def test_evaluate(self):
        engine = RiskScoringEngine()
        f1 = Finding("T1", Severity.CRITICAL, "test", "file", Confidence.HIGH)
        # 80 * 1.2 = 96
        verdict = engine.evaluate("job1", [f1])
        self.assertEqual(verdict.risk_score, 96)
        self.assertEqual(verdict.band, VerdictBand.MALICIOUS)
        
    def test_incomplete_stages(self):
        engine = RiskScoringEngine()
        verdict = engine.evaluate("job2", [], incomplete_critical_stages=True)
        self.assertEqual(verdict.band, VerdictBand.UNKNOWN)

if __name__ == "__main__":
    unittest.main()
