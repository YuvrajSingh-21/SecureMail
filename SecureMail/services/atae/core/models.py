from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from .enums import Severity, Confidence, VerdictBand

@dataclass
class Finding:
    technique_id: str
    severity: Severity
    description: str
    evidence_locator: str
    confidence: Confidence = Confidence.HIGH
    suppressed: bool = False
    suppression_reason: Optional[str] = None

@dataclass
class AttachmentVerdict:
    analysis_id: str
    risk_score: int
    band: VerdictBand
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)

@dataclass
class YaraMatch:
    rule: str
    namespace: str
    severity: str
    matches: List[str] = field(default_factory=list)

@dataclass
class ForensicRecord:
    analysis_id: str
    timestamp: str
    atae_version: str
    yara_corpus_version: str
    verdict: AttachmentVerdict
    file_identity: Dict[str, Any]
    ioc_list: List[Dict[str, str]] = field(default_factory=list)
    yara_matches: List[YaraMatch] = field(default_factory=list)
    entropy_profile: Dict[str, float] = field(default_factory=dict)
    incomplete_stages: List[str] = field(default_factory=list)
    completed_stages: List[str] = field(default_factory=list)
