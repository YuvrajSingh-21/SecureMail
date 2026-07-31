from typing import List, Dict
from ..core.models import Finding, AttachmentVerdict
from ..core.enums import Severity, Confidence, VerdictBand
from ..core.logger import get_atae_logger

logger = get_atae_logger("risk")

class RiskScoringConfig:
    def __init__(self, severity_weights: Dict[Severity, int] = None, confidence_multipliers: Dict[Confidence, float] = None):
        self.severity_weights = severity_weights or {
            Severity.INFO: 0,
            Severity.LOW: 10,
            Severity.MEDIUM: 25,
            Severity.HIGH: 45,
            Severity.CRITICAL: 80
        }
        self.confidence_multipliers = confidence_multipliers or {
            Confidence.LOW: 0.5,
            Confidence.MEDIUM: 1.0,
            Confidence.HIGH: 1.2
        }

class RiskScoringEngine:
    def __init__(self, config: RiskScoringConfig = None):
        self.config = config or RiskScoringConfig()

    def compute_score(self, findings: List[Finding]) -> int:
        score = 0.0
        for f in findings:
            if f.suppressed:
                continue
            base = self.config.severity_weights.get(f.severity, 0)
            mult = self.config.confidence_multipliers.get(f.confidence, 1.0)
            score += (base * mult)
            
        return min(100, int(score))
        
    def determine_band(self, score: int, incomplete_critical_stages: bool = False) -> VerdictBand:
        if incomplete_critical_stages:
            return VerdictBand.UNKNOWN
            
        if score < 20:
            return VerdictBand.CLEAN
        elif score < 50:
            return VerdictBand.SUSPICIOUS
        return VerdictBand.MALICIOUS

    def evaluate(self, analysis_id: str, findings: List[Finding], incomplete_critical_stages: bool = False) -> AttachmentVerdict:
        score = self.compute_score(findings)
        band = self.determine_band(score, incomplete_critical_stages)
        logger.info(f"Analysis {analysis_id} scored {score} (Band: {band.name})")
        
        return AttachmentVerdict(
            analysis_id=analysis_id,
            risk_score=score,
            band=band,
            findings=findings
        )
