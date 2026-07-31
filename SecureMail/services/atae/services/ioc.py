import re
from abc import ABC, abstractmethod
from typing import List, Dict
from ..core.context import AnalysisContext
from ..core.logger import get_atae_logger

logger = get_atae_logger("ioc")

class BaseIOCProvider(ABC):
    @abstractmethod
    def extract(self, data: bytes) -> List[Dict[str, str]]:
        pass

class RegexIOCProvider(BaseIOCProvider):
    def __init__(self):
        self.ipv4_regex = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.md5_regex = re.compile(rb'\b[a-fA-F0-9]{32}\b')
        
    def extract(self, data: bytes) -> List[Dict[str, str]]:
        iocs = []
        for match in self.ipv4_regex.finditer(data):
            ip = match.group().decode('utf-8', errors='ignore')
            if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
                iocs.append({"type": "ipv4", "value": ip})
                
        for match in self.md5_regex.finditer(data):
            hash_val = match.group().decode('utf-8', errors='ignore')
            iocs.append({"type": "md5", "value": hash_val})
            
        return iocs

class IOCExtractor:
    def __init__(self, providers: List[BaseIOCProvider] = None):
        self.providers = providers or [RegexIOCProvider()]

    def extract_iocs(self, data: bytes) -> List[Dict[str, str]]:
        all_iocs = []
        for provider in self.providers:
            all_iocs.extend(provider.extract(data))
        return all_iocs

    def run(self, file_bytes: bytes, context: AnalysisContext):
        found_iocs = self.extract_iocs(file_bytes)
        context.iocs.extend(found_iocs)
        logger.debug(f"Extracted {len(found_iocs)} IOCs for {context.analysis_id}")
        context.mark_stage_complete("ioc_extraction")
