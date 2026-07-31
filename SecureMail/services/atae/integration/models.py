from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from ..core.models import Finding

@dataclass
class AnalysisResult:
    analysis_id: str
    success: bool
    analyzer_name: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0

@dataclass
class AnalysisReport:
    analysis_id: str
    file_name: str
    file_size: int
    true_mime_type: str
    hashes: Dict[str, str] = field(default_factory=dict)
    
    analyzer_used: str = ""
    findings: List[Finding] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    entropy: float = 0.0
    
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    
    execution_time_ms: float = 0.0
    pipeline_version: str = "1.0.0"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
