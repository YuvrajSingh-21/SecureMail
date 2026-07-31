from dataclasses import dataclass, field
from typing import Dict
import os

@dataclass(frozen=True)
class ATAEConfig:
    max_nesting_depth: int = 5
    max_decompressed_size_mb: int = 500
    max_compression_ratio: int = 100
    temp_workspace_base: str = "/tmp/atae_workspaces"
    stage_timeout_seconds: int = 10
    job_timeout_seconds: int = 60
    version: str = "1.0.0"
    
    # Configurable MIME routing
    mime_routing: Dict[str, str] = field(default_factory=lambda: {
        "application/pdf": "pdf",
        "application/zip": "archive",
        "application/x-dosexec": "executable",
        "application/vnd.ms-office": "office"
    })

    def __post_init__(self):
        if self.max_nesting_depth <= 0:
            raise ValueError("max_nesting_depth must be positive")
        if self.max_decompressed_size_mb <= 0:
            raise ValueError("max_decompressed_size_mb must be positive")

    @classmethod
    def from_env(cls) -> "ATAEConfig":
        return cls(
            max_nesting_depth=int(os.getenv("ATAE_MAX_DEPTH", "5")),
            max_decompressed_size_mb=int(os.getenv("ATAE_MAX_DECOMPRESSED_MB", "500")),
            temp_workspace_base=os.getenv("ATAE_WORKSPACE_BASE", "/tmp/atae_workspaces")
        )

config = ATAEConfig.from_env()
