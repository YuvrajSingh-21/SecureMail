import re
import zlib
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from ..core.interfaces import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.models import Finding
from ..core.enums import Severity, Confidence
from ..core.exceptions import ATAEParserError
from ..core.logger import get_atae_logger
from ..core.config import config
from ..services.ioc import IOCExtractor
from ..services.entropy import EntropyEngine
from ..services.metadata import MetadataExtractor
from ..triage.magic import MagicByteDetection, FallbackMagicProvider

logger = get_atae_logger("pdf")

class PDFStream:
    def __init__(self, obj_id: int, filters: List[str], data: bytes):
        self.obj_id = obj_id
        self.filters = filters
        self.data = data

class PDFObject:
    def __init__(self, obj_id: int, data: bytes):
        self.obj_id = obj_id
        self.data = data

class PDFParserResult:
    def __init__(self):
        self.eof_count = 0
        self.object_count = 0
        self.keywords_found: List[bytes] = []
        self.streams: List[PDFStream] = []
        self.producer: Optional[str] = None
        self.raw_metadata: Dict[str, Any] = {}
        self.xrefs: List[Any] = []
        self.trailers: List[Any] = []

class BasePDFParser(ABC):
    @abstractmethod
    def parse(self, data: bytes) -> PDFParserResult:
        pass

class RegexPDFParser(BasePDFParser):
    def __init__(self, risk_keywords: List[bytes]):
        self.risk_keywords = risk_keywords
        self.obj_regex = re.compile(rb'\b\d+\s+\d+\s+obj\b')
        self.stream_regex = re.compile(rb'<<([^>]+)>>\s*stream[\r\n]+(.*?)[\r\n]+endstream', re.DOTALL)
        self.eof_regex = re.compile(rb'%%EOF')
        
    def parse(self, data: bytes) -> PDFParserResult:
        result = PDFParserResult()
        
        result.eof_count = len(self.eof_regex.findall(data))
        result.object_count = len(self.obj_regex.findall(data))
        
        for kw in self.risk_keywords:
            if kw in data:
                result.keywords_found.append(kw)
                
        for i, match in enumerate(self.stream_regex.finditer(data)):
            dict_data = match.group(1)
            stream_data = match.group(2)
            
            filters = []
            if b"/FlateDecode" in dict_data or b"/Fl" in dict_data:
                filters.append("FlateDecode")
                
            result.streams.append(PDFStream(obj_id=i, filters=filters, data=stream_data))
            
        producer_match = re.search(rb'/Producer\s*\(([^\)]+)\)', data)
        if producer_match:
            result.producer = producer_match.group(1).decode('utf-8', errors='ignore')
            result.raw_metadata["Producer"] = result.producer
            
        return result

class PDFAnalyzer(BaseAnalyzer):
    def __init__(self, parser: BasePDFParser = None):
        self.risk_keywords_map = {
            b"/JavaScript": ("PDF_JAVASCRIPT", Severity.HIGH, "Embedded JavaScript"),
            b"/JS": ("PDF_JAVASCRIPT", Severity.HIGH, "Embedded JavaScript"),
            b"/OpenAction": ("PDF_OPENACTION", Severity.HIGH, "OpenAction auto-execution"),
            b"/AA": ("PDF_AUTO_ACTION", Severity.HIGH, "Automatic Action"),
            b"/Launch": ("PDF_LAUNCH", Severity.CRITICAL, "Launch external application action"),
            b"/EmbeddedFiles": ("PDF_EMBEDDED_FILES", Severity.MEDIUM, "Embedded files"),
            b"/XFA": ("PDF_XFA_FORM", Severity.MEDIUM, "XFA Form"),
            b"/AcroForm": ("PDF_ACROFORM", Severity.LOW, "AcroForm"),
            b"/URI": ("PDF_URI", Severity.MEDIUM, "External URI/URL link"),
            b"/ObjStm": ("PDF_OBJSTM", Severity.LOW, "Object Streams (obfuscation technique)"),
            b"/Encrypt": ("PDF_ENCRYPTED", Severity.HIGH, "Encrypted/password-protected PDF"),
        }
        self.suspicious_producers = ["pdf-writer", "itext", "ghostscript"]
        
        self.parser = parser or RegexPDFParser(list(self.risk_keywords_map.keys()))
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.metadata_extractor = MetadataExtractor()
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        
    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        
        if not file_bytes.startswith(b"%PDF-"):
            raise ATAEParserError("Not a valid PDF document (missing header)")
            
        # Delegate parsing to abstraction
        result = self.parser.parse(file_bytes)
        
        # Integrate metadata extractor with raw bytes and parsed metadata
        self.metadata_extractor.run(file_bytes, context)
        if "pdf_metadata" not in context.metadata:
            context.metadata["pdf_metadata"] = {}
        context.metadata["pdf_metadata"].update(result.raw_metadata)

        # 1. Structural Checks
        if result.eof_count == 0:
            findings.append(Finding(
                technique_id="PDF_MALFORMED",
                severity=Severity.HIGH,
                description="Malformed PDF: No %%EOF marker",
                evidence_locator="structural",
                confidence=Confidence.HIGH
            ))
        elif result.eof_count > 1:
            findings.append(Finding(
                technique_id="PDF_INCREMENTAL_UPDATES",
                severity=Severity.LOW,
                description=f"Incremental updates detected: {result.eof_count} %%EOF markers",
                evidence_locator="structural",
                confidence=Confidence.HIGH
            ))
            
        max_objs = getattr(config, "max_pdf_objects", 10000)
        if result.object_count > max_objs:
            findings.append(Finding(
                technique_id="PDF_EXCESSIVE_OBJECTS",
                severity=Severity.MEDIUM,
                description=f"Excessive object count: {result.object_count}",
                evidence_locator="structural",
                confidence=Confidence.HIGH
            ))

        # 2. Keyword Detections
        for kw in result.keywords_found:
            tech_id, severity, desc = self.risk_keywords_map[kw]
            findings.append(Finding(
                technique_id=tech_id,
                severity=severity,
                description=desc,
                evidence_locator=kw.decode('utf-8'),
                confidence=Confidence.HIGH
            ))
                
        # 3. Stream Analysis
        for stream in result.streams:
            stream_data = stream.data
            
            if "FlateDecode" in stream.filters:
                try:
                    stream_data = zlib.decompress(stream_data)
                except zlib.error:
                    pass
            
            # Use cross-cutting services on decompressed stream
            self.entropy_engine.run(stream_data, context, profile_name=f"pdf_stream_{stream.obj_id}")
            self.ioc_extractor.run(stream_data, context)
            
            # Use MagicProvider to classify stream
            mime, desc = self.magic_detector.identify(stream_data[:2048])
            
            if mime == "application/x-dosexec" or stream_data.startswith(b"MZ"):
                findings.append(Finding(
                    technique_id="PDF_EMBEDDED_EXECUTABLE",
                    severity=Severity.CRITICAL,
                    description="Executable PE header (MZ) found inside PDF stream",
                    evidence_locator=f"stream_{stream.obj_id}",
                    confidence=Confidence.HIGH
                ))
                
        # 4. Suspicious metadata
        if result.producer:
            prod_lower = result.producer.lower()
            for susp in self.suspicious_producers:
                if susp in prod_lower:
                    findings.append(Finding(
                        technique_id="PDF_SUSPICIOUS_PRODUCER",
                        severity=Severity.MEDIUM,
                        description=f"Suspicious Producer string: {result.producer}",
                        evidence_locator="metadata",
                        confidence=Confidence.HIGH
                    ))

        context.mark_stage_complete("pdf_analysis")
        return findings
