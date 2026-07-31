import re
import base64
import binascii
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from ..core.interfaces import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.models import Finding
from ..core.enums import Severity, Confidence
from ..core.exceptions import ATAEParserError
from ..core.logger import get_atae_logger
from ..services.ioc import IOCExtractor
from ..services.entropy import EntropyEngine
from ..services.metadata import MetadataExtractor
from ..triage.magic import MagicByteDetection, FallbackMagicProvider

logger = get_atae_logger("generic")

@dataclass
class GenericEmbeddedObject:
    type: str
    offset: int
    data: bytes

@dataclass
class GenericEncoding:
    type: str
    decoded_value: bytes

@dataclass
class GenericParserResult:
    is_text: bool = False
    magic_mime: str = ""
    extension: str = ""
    printable_ratio: float = 0.0
    embedded_objects: List[GenericEmbeddedObject] = field(default_factory=list)
    encodings: List[GenericEncoding] = field(default_factory=list)
    large_string_regions: List[bytes] = field(default_factory=list)
    has_null_bytes_in_filename: bool = False
    has_double_extension: bool = False
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

class BaseGenericParser(ABC):
    def __init__(self, parser_logger):
        self.logger = parser_logger

    @abstractmethod
    def parse(self, data: bytes, filename: str) -> GenericParserResult:
        pass

class GenericParser(BaseGenericParser):
    def __init__(self, parser_logger):
        super().__init__(parser_logger)
        self.b64_regex = re.compile(rb'(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        self.hex_regex = re.compile(rb'(?:0x)?[0-9a-fA-F]{40,}')
        self.printable_regex = re.compile(rb'[\x20-\x7e]{100,}')
        self.signatures = {
            b"MZ": "PE Executable",
            b"\x7fELF": "ELF Executable",
            b"\xca\xfe\xba\xbe": "Mach-O Executable",
            b"\xfe\xed\xfa\xce": "Mach-O Executable",
            b"PK\x03\x04": "ZIP Archive",
            b"%PDF-": "PDF Document",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "OLE Office Document",
            b"#!/bin/bash": "Shell Script",
            b"#!/bin/sh": "Shell Script",
            b"<html": "HTML Document"
        }
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())

    def parse(self, data: bytes, filename: str) -> GenericParserResult:
        result = GenericParserResult()
        
        # Filename checks
        if filename:
            if '\x00' in filename:
                result.has_null_bytes_in_filename = True
                filename = filename.replace('\x00', '')
                
            parts = filename.split('.')
            if len(parts) > 2:
                # Naive double extension check (e.g. file.pdf.exe)
                if parts[-2].lower() not in ('tar'):
                    result.has_double_extension = True
            
            if len(parts) > 1:
                result.extension = parts[-1].lower()

        # Identify magic MIME of the main file
        mime, _ = self.magic_detector.identify(data[:2048])
        result.magic_mime = mime

        if not data:
            return result

        # Text/binary ratio
        printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
        result.printable_ratio = printable / len(data)
        result.is_text = result.printable_ratio > 0.85

        # Encodings
        for b64 in self.b64_regex.finditer(data):
            try:
                decoded = base64.b64decode(b64.group())
                result.encodings.append(GenericEncoding("base64", decoded))
            except Exception:
                pass
                
        for hx in self.hex_regex.finditer(data):
            match = hx.group()
            if match.startswith(b"0x"):
                match = match[2:]
            try:
                decoded = binascii.unhexlify(match)
                result.encodings.append(GenericEncoding("hex", decoded))
            except Exception:
                pass

        # Printable regions
        for region in self.printable_regex.finditer(data):
            result.large_string_regions.append(region.group())

        # Embedded objects
        for sig, name in self.signatures.items():
            idx = data.find(sig)
            while idx != -1:
                # Capture a chunk for analysis
                chunk = data[idx:idx+4096]
                result.embedded_objects.append(GenericEmbeddedObject(name, idx, chunk))
                idx = data.find(sig, idx + len(sig))

        return result

class GenericAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.metadata_extractor = MetadataExtractor()
        self.logger = logger
        
        self.mime_ext_map = {
            "application/x-dosexec": ["exe", "dll", "sys", "scr"],
            "application/x-executable": ["elf", "bin", "so"],
            "application/pdf": ["pdf"],
            "application/zip": ["zip", "docx", "xlsx", "pptx", "jar", "apk"],
            "image/jpeg": ["jpg", "jpeg"],
            "image/png": ["png"],
            "text/plain": ["txt", "log", "csv"]
        }

    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        
        parser = GenericParser(self.logger)
        result = parser.parse(file_bytes, context.declared_filename)
        
        self.metadata_extractor.run(file_bytes, context)
        self.ioc_extractor.run(file_bytes, context)
        self.entropy_engine.run(file_bytes, context, profile_name="generic_whole")
        
        # File identity findings
        if result.magic_mime == "application/octet-stream" and not result.is_text:
            findings.append(Finding(
                technique_id="GENERIC_UNKNOWN_BINARY",
                severity=Severity.LOW,
                description="File type is unknown and content is binary",
                evidence_locator="magic",
                confidence=Confidence.HIGH
            ))
            
        if result.has_null_bytes_in_filename:
            findings.append(Finding(
                technique_id="GENERIC_NULL_BYTE_FILENAME",
                severity=Severity.HIGH,
                description="Filename contains null bytes, indicative of evasion",
                evidence_locator="filename",
                confidence=Confidence.HIGH
            ))
            
        if result.has_double_extension:
            findings.append(Finding(
                technique_id="GENERIC_DOUBLE_EXTENSION",
                severity=Severity.MEDIUM,
                description="Filename contains multiple extensions",
                evidence_locator="filename",
                confidence=Confidence.HIGH
            ))
            
        # Extension mismatch
        if result.extension and result.magic_mime in self.mime_ext_map:
            valid_exts = self.mime_ext_map[result.magic_mime]
            if result.extension not in valid_exts:
                findings.append(Finding(
                    technique_id="GENERIC_EXTENSION_MISMATCH",
                    severity=Severity.MEDIUM,
                    description=f"File extension .{result.extension} does not match detected type {result.magic_mime}",
                    evidence_locator="extension",
                    confidence=Confidence.HIGH
                ))

        # Size and text mixture
        if len(file_bytes) > 50 * 1024 * 1024:
            findings.append(Finding(
                technique_id="GENERIC_OVERSIZED_FILE",
                severity=Severity.MEDIUM,
                description="File size exceeds typical analysis thresholds",
                evidence_locator="size",
                confidence=Confidence.HIGH
            ))
            
        if not result.is_text and len(result.large_string_regions) > 5:
            findings.append(Finding(
                technique_id="GENERIC_MIXED_CONTENT",
                severity=Severity.LOW,
                description="Binary file contains numerous large printable string regions",
                evidence_locator="strings",
                confidence=Confidence.LOW
            ))
            
        for region in result.large_string_regions:
            self.ioc_extractor.run(region, context)

        # Embedded objects
        for obj in result.embedded_objects:
            findings.append(Finding(
                technique_id="GENERIC_EMBEDDED_OBJECT",
                severity=Severity.HIGH,
                description=f"Embedded {obj.type} signature found",
                evidence_locator=f"offset_{obj.offset}",
                confidence=Confidence.HIGH
            ))
            self.entropy_engine.run(obj.data, context, profile_name="generic_embedded")
            self.ioc_extractor.run(obj.data, context)

        # Encodings
        if len(result.encodings) > 0:
            findings.append(Finding(
                technique_id="GENERIC_ENCODED_BLOB",
                severity=Severity.MEDIUM,
                description=f"Found {len(result.encodings)} base64/hex encoded blobs",
                evidence_locator="encodings",
                confidence=Confidence.HIGH
            ))
            for enc in result.encodings:
                self.ioc_extractor.run(enc.decoded_value, context)
                
                # Check for nested PE
                if enc.decoded_value.startswith(b"MZ"):
                    findings.append(Finding(
                        technique_id="GENERIC_ENCODED_EXECUTABLE",
                        severity=Severity.CRITICAL,
                        description="Decoded blob contains a PE executable",
                        evidence_locator="encoding",
                        confidence=Confidence.HIGH
                    ))

        # We rely on the EntropyEngine for "High entropy files" detection
        # The profile "generic_whole" will generate ENTROPY_HIGH if > 7.5

        context.mark_stage_complete("generic_analysis")
        return findings
