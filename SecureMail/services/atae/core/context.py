from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import time
from .models import Finding
from .config import config

@dataclass
class AnalysisContext:
    analysis_id: str
    file_path: str
    declared_filename: str
    declared_mime_type: str
    
    workspace_path: Optional[str] = None
    true_mime_type: Optional[str] = None
    true_human_readable_type: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    
    current_depth: int = 0
    cumulative_decompressed_bytes: int = 0
    
    findings: List[Finding] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    completed_stages: List[str] = field(default_factory=list)
    incomplete_stages: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        
    def check_limits(self, added_size: int = 0):
        from .exceptions import ATAEResourceExhaustionError
        if self.current_depth > config.max_nesting_depth:
            raise ATAEResourceExhaustionError(f"Max nesting depth {config.max_nesting_depth} exceeded")
        if (self.cumulative_decompressed_bytes + added_size) > (config.max_decompressed_size_mb * 1024 * 1024):
            raise ATAEResourceExhaustionError("Max decompressed size exceeded")
        self.cumulative_decompressed_bytes += added_size
        
    def mark_stage_complete(self, stage_name: str):
        self.completed_stages.append(stage_name)
        
    def mark_stage_incomplete(self, stage_name: str):
        self.incomplete_stages.append(stage_name)
