from abc import ABC, abstractmethod
from typing import Dict, Any
from ..core.context import AnalysisContext
from ..core.models import Finding
from ..core.enums import Severity, Confidence
from ..core.logger import get_atae_logger

logger = get_atae_logger("threat_intel")

class ThreatIntelProvider(ABC):
    @abstractmethod
    def lookup_hash(self, sha256: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_url(self, url: str) -> Dict[str, Any]:
        pass

class MockThreatIntelProvider(ThreatIntelProvider):
    def lookup_hash(self, sha256: str) -> Dict[str, Any]:
        if sha256 == "bad_hash":
            return {"known": True, "malicious": True, "positives": 45}
        return {"known": False}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return {"known": False}

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return {"known": False}

    def lookup_url(self, url: str) -> Dict[str, Any]:
        return {"known": False}

class ThreatIntelligenceClient:
    def __init__(self, provider: ThreatIntelProvider):
        self.provider = provider

    def run(self, context: AnalysisContext):
        sha256 = context.hashes.get("sha256")
        if not sha256:
            logger.warning(f"No SHA256 found in context {context.analysis_id}, skipping TI lookup")
            context.mark_stage_incomplete("threat_intel")
            return
            
        result = self.provider.lookup_hash(sha256)
        if result.get("malicious"):
            finding = Finding(
                technique_id="TI_KNOWN_MALICIOUS",
                severity=Severity.CRITICAL,
                description=f"File hash known malicious: {result.get('positives')} positives",
                evidence_locator=f"sha256:{sha256}",
                confidence=Confidence.HIGH
            )
            context.add_finding(finding)
            
        context.metadata["threat_intel"] = result
        context.mark_stage_complete("threat_intel")
