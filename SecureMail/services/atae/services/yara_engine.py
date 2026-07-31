from abc import ABC, abstractmethod
from typing import List
from ..core.context import AnalysisContext
from ..core.models import Finding, YaraMatch
from ..core.enums import Severity, Confidence
from ..core.logger import get_atae_logger

logger = get_atae_logger("yara")

class YaraProvider(ABC):
    @abstractmethod
    def match(self, data: bytes) -> List[YaraMatch]:
        pass

class MockYaraProvider(YaraProvider):
    def match(self, data: bytes) -> List[YaraMatch]:
        if b"MALICIOUS_STRING" in data:
            return [YaraMatch(rule="Detect_Malicious_String", namespace="test", severity="HIGH")]
        return []

class YaraEngine:
    def __init__(self, provider: YaraProvider):
        self.provider = provider
        
    def run(self, file_bytes: bytes, context: AnalysisContext):
        matches = self.provider.match(file_bytes)
        for match in matches:
            severity_str = match.severity.upper()
            try:
                severity = Severity[severity_str]
            except KeyError:
                severity = Severity.MEDIUM
                
            finding = Finding(
                technique_id=f"YARA_{match.rule}",
                severity=severity,
                description=f"YARA match: {match.rule} in namespace {match.namespace}",
                evidence_locator="whole_file",
                confidence=Confidence.HIGH
            )
            context.add_finding(finding)
            
            if "yara_matches" not in context.metadata:
                context.metadata["yara_matches"] = []
            context.metadata["yara_matches"].append(match)
            
        logger.debug(f"YARA engine found {len(matches)} matches for {context.analysis_id}")
        context.mark_stage_complete("yara_scan")
