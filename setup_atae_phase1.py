import os

base = "SecureMail/services/atae"
os.makedirs(f"{base}/core", exist_ok=True)
os.makedirs(f"{base}/triage", exist_ok=True)

# __init__.py files
open(f"{base}/__init__.py", "w").close()
open(f"{base}/core/__init__.py", "w").close()
open(f"{base}/triage/__init__.py", "w").close()

with open(f"{base}/core/exceptions.py", "w") as f:
    f.write("""class ATAEError(Exception):
    \"\"\"Base exception for ATAE.\"\"\"
    pass

class ATAEParserError(ATAEError):
    \"\"\"Raised when an analyzer fails to parse a file structurally.\"\"\"
    pass

class ATAETimeoutError(ATAEError):
    \"\"\"Raised when an analysis stage exceeds its time limit.\"\"\"
    pass

class ATAEResourceExhaustionError(ATAEError):
    \"\"\"Raised when resource limits (size, depth, memory) are exceeded.\"\"\"
    pass

class ATAEArchiveBombError(ATAEResourceExhaustionError):
    \"\"\"Raised when an archive bomb is detected.\"\"\"
    pass
""")

with open(f"{base}/core/config.py", "w") as f:
    f.write("""from dataclasses import dataclass, field
import os

@dataclass
class ATAEConfig:
    max_nesting_depth: int = 5
    max_decompressed_size_mb: int = 500
    max_compression_ratio: int = 100
    temp_workspace_base: str = "/tmp/atae_workspaces"
    stage_timeout_seconds: int = 10
    job_timeout_seconds: int = 60

    @classmethod
    def from_env(cls) -> "ATAEConfig":
        return cls(
            max_nesting_depth=int(os.getenv("ATAE_MAX_DEPTH", "5")),
            max_decompressed_size_mb=int(os.getenv("ATAE_MAX_DECOMPRESSED_MB", "500")),
            temp_workspace_base=os.getenv("ATAE_WORKSPACE_BASE", "/tmp/atae_workspaces")
        )

config = ATAEConfig.from_env()
""")

with open(f"{base}/core/logger.py", "w") as f:
    f.write("""import logging

def get_atae_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"atae.{name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - ATAE - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    return logger
""")

with open(f"{base}/core/models.py", "w") as f:
    f.write("""from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class Finding:
    technique_id: str
    severity: str  # e.g., 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description: str
    evidence_locator: str
    confidence: str = "HIGH"
    suppressed: bool = False
    suppression_reason: Optional[str] = None

@dataclass
class AttachmentVerdict:
    analysis_id: str
    risk_score: int
    band: str  # 'CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)

@dataclass
class ForensicRecord:
    analysis_id: str
    timestamp: str
    verdict: AttachmentVerdict
    file_identity: Dict[str, Any]
    ioc_list: List[Dict[str, str]] = field(default_factory=list)
    yara_matches: List[Dict[str, str]] = field(default_factory=list)
    incomplete_stages: List[str] = field(default_factory=list)
""")

with open(f"{base}/core/context.py", "w") as f:
    f.write("""from dataclasses import dataclass, field
from typing import List, Dict, Any
from .models import Finding
from .config import config

@dataclass
class AnalysisContext:
    analysis_id: str
    file_path: str
    declared_filename: str
    declared_mime_type: str
    
    current_depth: int = 0
    cumulative_decompressed_bytes: int = 0
    
    findings: List[Finding] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        
    def check_limits(self, added_size: int = 0):
        from .exceptions import ATAEResourceExhaustionError
        if self.current_depth > config.max_nesting_depth:
            raise ATAEResourceExhaustionError(f"Max nesting depth {config.max_nesting_depth} exceeded")
        if (self.cumulative_decompressed_bytes + added_size) > (config.max_decompressed_size_mb * 1024 * 1024):
            raise ATAEResourceExhaustionError("Max decompressed size exceeded")
        self.cumulative_decompressed_bytes += added_size
""")

with open(f"{base}/core/interfaces.py", "w") as f:
    f.write("""from abc import ABC, abstractmethod
from typing import List
from .context import AnalysisContext
from .models import Finding

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        \"\"\"
        Statically analyze file bytes and return a list of findings.
        The context is provided to attach deeper artifacts (e.g., extracted IOCs)
        and track limits.
        \"\"\"
        pass
""")

with open(f"{base}/core/registry.py", "w") as f:
    f.write("""from typing import Dict, Type
from .interfaces import BaseAnalyzer

class AnalyzerRegistry:
    _registry: Dict[str, Type[BaseAnalyzer]] = {}

    @classmethod
    def register(cls, file_type: str, analyzer_cls: Type[BaseAnalyzer]):
        cls._registry[file_type.lower()] = analyzer_cls

    @classmethod
    def get_analyzer(cls, file_type: str) -> Type[BaseAnalyzer]:
        return cls._registry.get(file_type.lower())

    @classmethod
    def clear(cls):
        cls._registry.clear()
""")

with open(f"{base}/triage/workspace.py", "w") as f:
    f.write("""import os
import shutil
import uuid
import stat
from ..core.config import config
from ..core.logger import get_atae_logger

logger = get_atae_logger("workspace")

class TemporaryWorkspaceManager:
    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or config.temp_workspace_base
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
            # Ensure only the app user has access
            os.chmod(self.base_dir, stat.S_IRWXU)

    def create_workspace(self, analysis_id: str) -> str:
        safe_id = "".join(c for c in analysis_id if c.isalnum() or c in ("-", "_"))
        if not safe_id:
            safe_id = str(uuid.uuid4())
            
        path = os.path.join(self.base_dir, safe_id)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, stat.S_IRWXU)
        logger.info(f"Created secure workspace at {path}")
        return path

    def secure_wipe(self, path: str):
        \"\"\"
        Securely wipe the directory.
        For Phase 1, we overwrite files with zeros before deletion.
        \"\"\"
        if not os.path.exists(path):
            return
        
        try:
            for root, dirs, files in os.walk(path):
                for f in files:
                    file_path = os.path.join(root, f)
                    try:
                        size = os.path.getsize(file_path)
                        with open(file_path, "wb") as fd:
                            fd.write(b'\\x00' * size)
                    except Exception as e:
                        logger.warning(f"Could not wipe {file_path}: {e}")
            shutil.rmtree(path)
            logger.info(f"Securely wiped and removed workspace {path}")
        except Exception as e:
            logger.error(f"Failed to wipe workspace {path}: {e}")
""")

with open(f"{base}/triage/hashing.py", "w") as f:
    f.write("""import hashlib
from typing import Dict

class HashingService:
    @staticmethod
    def compute_hashes(file_bytes: bytes) -> Dict[str, str]:
        \"\"\"
        Compute MD5, SHA1, and SHA256 hashes for the given bytes.
        \"\"\"
        return {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }
""")

with open(f"{base}/triage/magic.py", "w") as f:
    f.write("""from typing import Tuple
from ..core.logger import get_atae_logger

logger = get_atae_logger("magic")

class FileTypeIdentification:
    @staticmethod
    def identify(file_bytes: bytes) -> Tuple[str, str]:
        \"\"\"
        Identify true file type via magic bytes.
        For phase 1, uses a simplistic byte prefix lookup. 
        In production, this would bind to libmagic (python-magic).
        Returns (mime_type, human_readable_type).
        \"\"\"
        if file_bytes.startswith(b"\\x25\\x50\\x44\\x46"):
            return "application/pdf", "PDF Document"
        if file_bytes.startswith(b"\\x50\\x4B\\x03\\x04"):
            # Could be ZIP, DOCX, XLSM, APK, etc.
            return "application/zip", "ZIP Archive / OOXML"
        if file_bytes.startswith(b"\\x4D\\x5A"):
            return "application/x-dosexec", "PE Executable"
        if file_bytes.startswith(b"\\xD0\\xCF\\x11\\xE0\\xA1\\xB1\\x1A\\xE1"):
            return "application/vnd.ms-office", "OLE Compound File"
            
        return "application/octet-stream", "Unknown Data"

class MagicByteDetection:
    @staticmethod
    def detect_fake_extension(true_mime: str, declared_filename: str) -> bool:
        \"\"\"
        Check if the true mime type reasonably matches the declared file extension.
        Returns True if a fake extension is detected.
        \"\"\"
        if not declared_filename:
            return False
            
        ext = declared_filename.split(".")[-1].lower() if "." in declared_filename else ""
        
        # Simple mapping for Phase 1
        mapping = {
            "pdf": ["application/pdf"],
            "zip": ["application/zip"],
            "docx": ["application/zip"], # OOXML is a zip
            "xlsx": ["application/zip"],
            "exe": ["application/x-dosexec"],
            "doc": ["application/vnd.ms-office"],
            "xls": ["application/vnd.ms-office"],
        }
        
        allowed_mimes = mapping.get(ext)
        if allowed_mimes and true_mime not in allowed_mimes:
            return True
        return False
""")

with open(f"{base}/triage/router.py", "w") as f:
    f.write("""from typing import Optional, Type
from ..core.registry import AnalyzerRegistry
from ..core.interfaces import BaseAnalyzer

class AttachmentRouter:
    @staticmethod
    def route(true_mime: str) -> Optional[Type[BaseAnalyzer]]:
        \"\"\"
        Return the appropriate analyzer class based on the true mime type.
        \"\"\"
        # Map mime types to internal category names for the registry
        mime_mapping = {
            "application/pdf": "pdf",
            "application/zip": "archive",  # Or OOXML depending on deep inspection
            "application/x-dosexec": "executable",
            "application/vnd.ms-office": "office"
        }
        
        category = mime_mapping.get(true_mime, "generic")
        return AnalyzerRegistry.get_analyzer(category)
""")
