from abc import ABC, abstractmethod
from typing import Dict, Any, List
from ..core.context import AnalysisContext
from ..core.logger import get_atae_logger

logger = get_atae_logger("metadata")

class BaseMetadataProvider(ABC):
    @abstractmethod
    def extract(self, file_bytes: bytes) -> Dict[str, Any]:
        pass

class StandardMetadataProvider(BaseMetadataProvider):
    def extract(self, file_bytes: bytes) -> Dict[str, Any]:
        return {
            "size_bytes": len(file_bytes),
            "starts_with_hex": file_bytes[:8].hex()
        }

class MetadataExtractor:
    def __init__(self, providers: List[BaseMetadataProvider] = None):
        self.providers = providers or [StandardMetadataProvider()]

    def extract(self, file_bytes: bytes) -> Dict[str, Any]:
        combined_meta = {}
        for provider in self.providers:
            combined_meta.update(provider.extract(file_bytes))
        return combined_meta

    def run(self, file_bytes: bytes, context: AnalysisContext):
        meta = self.extract(file_bytes)
        if "basic_file_metadata" not in context.metadata:
            context.metadata["basic_file_metadata"] = {}
        context.metadata["basic_file_metadata"].update(meta)
        logger.debug(f"Extracted metadata for {context.analysis_id}")
        context.mark_stage_complete("metadata_extraction")
