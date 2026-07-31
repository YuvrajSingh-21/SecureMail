import io
import zipfile
import xml.etree.ElementTree as ET
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

logger = get_atae_logger("office")

@dataclass
class OfficeRelationship:
    id: str
    type: str
    target: str
    target_mode: str
    source_file: str

@dataclass
class OfficeEmbeddedObject:
    path: str
    data: bytes
    is_ole: bool = False
    is_activex: bool = False

@dataclass
class OfficeVBAIndicator:
    name: str
    description: str

@dataclass
class OfficeHiddenElement:
    name: str
    element_type: str
    description: str

@dataclass
class OfficeParserResult:
    is_ooxml: bool
    is_ole2: bool
    is_encrypted: bool = False
    relationships: List[OfficeRelationship] = field(default_factory=list)
    embedded_objects: List[OfficeEmbeddedObject] = field(default_factory=list)
    vba_indicators: List[OfficeVBAIndicator] = field(default_factory=list)
    hidden_elements: List[OfficeHiddenElement] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_bytes: bytes = b""

class BaseOfficeParser(ABC):
    @abstractmethod
    def parse(self, data: bytes) -> OfficeParserResult:
        pass

class OOXMLParser(BaseOfficeParser):
    def __init__(self, parser_logger):
        self.logger = parser_logger
        
    def _parse_xml(self, data: bytes) -> Optional[ET.Element]:
        try:
            return ET.fromstring(data)
        except ET.ParseError as e:
            self.logger.warning(f"XML parse error: {e}")
            return None

    def _get_tag_name(self, elem: ET.Element) -> str:
        return elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag

    def parse(self, data: bytes) -> OfficeParserResult:
        result = OfficeParserResult(is_ooxml=True, is_ole2=False, raw_bytes=data)
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise ATAEParserError(f"Invalid OOXML document: {e}")
            
        for info in zf.infolist():
            name = info.filename.lower()
            
            # VBA Macros
            if name.endswith("vbaproject.bin") or "macros" in name:
                result.vba_indicators.append(OfficeVBAIndicator(name=info.filename, description="VBA Project Binary"))
                
            # Embedded objects
            if "embeddings" in name or "media" in name:
                try:
                    obj_data = zf.read(info.filename)
                    is_ole = "embeddings/ole" in name
                    is_activex = "activex" in name
                    result.embedded_objects.append(OfficeEmbeddedObject(
                        path=info.filename,
                        data=obj_data,
                        is_ole=is_ole,
                        is_activex=is_activex
                    ))
                except Exception as e:
                    self.logger.error(f"Failed to read embedded object {info.filename}: {e}")

            # Relationships
            if name.endswith(".rels"):
                try:
                    rel_data = zf.read(info.filename)
                    root = self._parse_xml(rel_data)
                    if root is not None:
                        for child in root:
                            if self._get_tag_name(child) == "Relationship":
                                target = child.attrib.get("Target", "")
                                mode = child.attrib.get("TargetMode", "Internal")
                                rel_type = child.attrib.get("Type", "")
                                rel_id = child.attrib.get("Id", "")
                                result.relationships.append(OfficeRelationship(
                                    id=rel_id,
                                    type=rel_type,
                                    target=target,
                                    target_mode=mode,
                                    source_file=info.filename
                                ))
                except Exception as e:
                    self.logger.error(f"Failed to parse relationships in {info.filename}: {e}")

            # Hidden Sheets/Slides
            if name.endswith("workbook.xml") or name.endswith("presentation.xml"):
                try:
                    xml_data = zf.read(info.filename)
                    root = self._parse_xml(xml_data)
                    if root is not None:
                        for elem in root.iter():
                            state = elem.attrib.get("state")
                            if state in ("hidden", "veryHidden"):
                                elem_name = elem.attrib.get("name", "Unknown")
                                result.hidden_elements.append(OfficeHiddenElement(
                                    name=elem_name,
                                    element_type=self._get_tag_name(elem),
                                    description=f"Hidden state: {state}"
                                ))
                except Exception as e:
                    self.logger.error(f"Failed to parse XML in {info.filename}: {e}")
                    
        return result

class OLE2Parser(BaseOfficeParser):
    def __init__(self, parser_logger):
        self.logger = parser_logger
        
    def _traverse_directories(self):
        """Prepare parser interface for future OLE directory traversal."""
        pass

    def parse(self, data: bytes) -> OfficeParserResult:
        result = OfficeParserResult(is_ooxml=False, is_ole2=True, raw_bytes=data)
        
        # We don't implement a full CFB parser here yet, use byte search to extract indicators.
        if b"DataSpaces" in data and b"EncryptedPackage" in data:
            result.is_encrypted = True
            
        if b"VBA" in data or b"_VBA_PROJECT" in data or b"vbaProject" in data:
            result.vba_indicators.append(OfficeVBAIndicator(name="VBA_PROJECT", description="VBA Macros signature found"))
            
        if b"AutoOpen" in data or b"AutoExec" in data or b"Document_Open" in data or b"Workbook_Open" in data:
            result.vba_indicators.append(OfficeVBAIndicator(name="AutoExec", description="Auto-execution VBA macro trigger signature"))
            
        if b"DDEAUTO" in data or b"DDE " in data:
            result.vba_indicators.append(OfficeVBAIndicator(name="DDE", description="DDE execution signature found"))
            
        return result

class OfficeAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.metadata_extractor = MetadataExtractor()
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        self.logger = logger

    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        if len(file_bytes) < 8:
            raise ATAEParserError("File too small")
            
        magic = file_bytes[:8]
        if magic.startswith(b"PK\x03\x04"):
            parser = OOXMLParser(self.logger)
        elif magic == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            parser = OLE2Parser(self.logger)
        else:
            raise ATAEParserError("Not a recognized Office document structure")
            
        result = parser.parse(file_bytes)
        self.metadata_extractor.run(file_bytes, context)

        if result.is_encrypted:
            findings.append(Finding(
                technique_id="OFFICE_ENCRYPTED",
                severity=Severity.HIGH,
                description="Encrypted OLE2 Office document (password protected)",
                evidence_locator="EncryptedPackage",
                confidence=Confidence.HIGH
            ))
            
        for vba in result.vba_indicators:
            if vba.name == "AutoExec":
                tech = "OFFICE_AUTO_EXEC"
                sev = Severity.CRITICAL
            elif vba.name == "DDE":
                tech = "OFFICE_DDE_FIELD"
                sev = Severity.HIGH
            else:
                tech = "OFFICE_VBA_MACROS"
                sev = Severity.HIGH
                
            findings.append(Finding(
                technique_id=tech,
                severity=sev,
                description=vba.description,
                evidence_locator=vba.name,
                confidence=Confidence.HIGH
            ))
            
        for rel in result.relationships:
            if rel.target_mode == "External":
                if rel.type.endswith("attachedTemplate"):
                    findings.append(Finding(
                        technique_id="OFFICE_EXTERNAL_TEMPLATE",
                        severity=Severity.HIGH,
                        description=f"External template injection to: {rel.target}",
                        evidence_locator=rel.source_file,
                        confidence=Confidence.HIGH
                    ))
                else:
                    findings.append(Finding(
                        technique_id="OFFICE_EXTERNAL_LINK",
                        severity=Severity.MEDIUM,
                        description=f"External package relationship to: {rel.target}",
                        evidence_locator=rel.source_file,
                        confidence=Confidence.HIGH
                    ))
                    
        for hidden in result.hidden_elements:
            findings.append(Finding(
                technique_id="OFFICE_HIDDEN_SHEET",
                severity=Severity.LOW,
                description=f"{hidden.description} for {hidden.name}",
                evidence_locator=hidden.element_type,
                confidence=Confidence.HIGH
            ))
            
        for obj in result.embedded_objects:
            if obj.is_ole:
                findings.append(Finding(
                    technique_id="OFFICE_EMBEDDED_OLE",
                    severity=Severity.MEDIUM,
                    description="Embedded OLE object found",
                    evidence_locator=obj.path,
                    confidence=Confidence.HIGH
                ))
            if obj.is_activex:
                findings.append(Finding(
                    technique_id="OFFICE_ACTIVEX",
                    severity=Severity.MEDIUM,
                    description="ActiveX controls found",
                    evidence_locator=obj.path,
                    confidence=Confidence.HIGH
                ))
                
            self.entropy_engine.run(obj.data, context, profile_name=f"office_embedded_{obj.path}")
            self.ioc_extractor.run(obj.data, context)
            
            mime, _ = self.magic_detector.identify(obj.data[:2048])
            if mime == "application/x-dosexec" or obj.data.startswith(b"MZ"):
                findings.append(Finding(
                    technique_id="OFFICE_EMBEDDED_EXECUTABLE",
                    severity=Severity.CRITICAL,
                    description="Embedded Executable (PE) found",
                    evidence_locator=obj.path,
                    confidence=Confidence.HIGH
                ))
            elif obj.data.startswith(b"PK\x03\x04"):
                findings.append(Finding(
                    technique_id="OFFICE_EMBEDDED_ARCHIVE",
                    severity=Severity.MEDIUM,
                    description="Embedded ZIP archive found",
                    evidence_locator=obj.path,
                    confidence=Confidence.HIGH
                ))

        if result.is_ole2:
            self.ioc_extractor.run(result.raw_bytes, context)
            self.entropy_engine.run(result.raw_bytes, context, profile_name="office_ole2")
            
        context.mark_stage_complete("office_analysis")
        return findings
