from abc import ABC, abstractmethod
from typing import Tuple
from ..core.logger import get_atae_logger

logger = get_atae_logger("magic")

class BaseMagicProvider(ABC):
    @abstractmethod
    def identify(self, file_bytes: bytes) -> Tuple[str, str]:
        pass

class FallbackMagicProvider(BaseMagicProvider):
    def identify(self, file_bytes: bytes) -> Tuple[str, str]:
        if file_bytes.startswith(b"\x25\x50\x44\x46"):
            return "application/pdf", "PDF Document"
        if file_bytes.startswith(b"\x50\x4B\x03\x04"):
            return "application/zip", "ZIP Archive / OOXML"
        if file_bytes.startswith(b"\x4D\x5A"):
            return "application/x-dosexec", "PE Executable"
        if file_bytes.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            return "application/vnd.ms-office", "OLE Compound File"
        return "application/octet-stream", "Unknown Data"

class MagicByteDetection:
    def __init__(self, provider: BaseMagicProvider = None):
        self.provider = provider or FallbackMagicProvider()

    def identify(self, file_bytes: bytes) -> Tuple[str, str]:
        return self.provider.identify(file_bytes)

    @staticmethod
    def detect_fake_extension(true_mime: str, declared_filename: str) -> bool:
        if not declared_filename:
            return False
            
        ext = declared_filename.split(".")[-1].lower() if "." in declared_filename else ""
        
        mapping = {
            "pdf": ["application/pdf"],
            "zip": ["application/zip"],
            "docx": ["application/zip"],
            "xlsx": ["application/zip"],
            "exe": ["application/x-dosexec"],
            "doc": ["application/vnd.ms-office"],
            "xls": ["application/vnd.ms-office"],
        }
        
        allowed_mimes = mapping.get(ext)
        if allowed_mimes and true_mime not in allowed_mimes:
            return True
        return False
