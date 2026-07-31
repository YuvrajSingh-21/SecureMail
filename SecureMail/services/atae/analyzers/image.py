import struct
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

logger = get_atae_logger("image")

@dataclass
class ImageChunk:
    name: str
    length: int
    offset: int
    data: bytes = b""

@dataclass
class ImageSegment:
    name: str
    length: int
    offset: int
    data: bytes = b""

@dataclass
class ImageMetadata:
    type: str
    data: bytes

@dataclass
class ImageColorProfile:
    name: str
    data: bytes

@dataclass
class ImageTrailer:
    offset: int
    data: bytes

@dataclass
class ImageEmbeddedObject:
    type: str
    offset: int
    data: bytes

@dataclass
class ImageParserResult:
    format: str
    is_valid: bool = True
    width: int = 0
    height: int = 0
    bit_depth: int = 0
    color_type: int = 0
    compression: int = 0
    chunks: List[ImageChunk] = field(default_factory=list)
    segments: List[ImageSegment] = field(default_factory=list)
    metadata: List[ImageMetadata] = field(default_factory=list)
    embedded_objects: List[ImageEmbeddedObject] = field(default_factory=list)
    trailers: List[ImageTrailer] = field(default_factory=list)
    color_profiles: List[ImageColorProfile] = field(default_factory=list)
    has_exif: bool = False
    has_xmp: bool = False
    has_iptc: bool = False
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

class BaseImageParser(ABC):
    def __init__(self, parser_logger):
        self.logger = parser_logger

    @abstractmethod
    def parse(self, data: bytes) -> ImageParserResult:
        pass

class PNGParser(BaseImageParser):
    def parse(self, data: bytes) -> ImageParserResult:
        result = ImageParserResult(format="PNG")
        if len(data) < 8 or data[:8] != b'\x89PNG\r\n\x1a\n':
            result.is_valid = False
            return result

        offset = 8
        found_ihdr = False
        found_iend = False
        
        while offset < len(data) and not found_iend:
            if offset + 8 > len(data):
                result.is_valid = False
                break
                
            length = struct.unpack_from('>I', data, offset)[0]
            chunk_type = data[offset+4:offset+8].decode('ascii', errors='replace')
            
            if length > 100 * 1024 * 1024: # 100MB chunk anomaly
                result.is_valid = False
                break
                
            if offset + 8 + length + 4 > len(data):
                result.is_valid = False
                break
                
            chunk_data = data[offset+8:offset+8+length]
            result.chunks.append(ImageChunk(chunk_type, length, offset, chunk_data))
            
            if chunk_type == 'IHDR':
                if found_ihdr:
                    result.is_valid = False # duplicate IHDR
                else:
                    found_ihdr = True
                    if length >= 13:
                        result.width, result.height, result.bit_depth, result.color_type, result.compression = struct.unpack_from('>IIBBB', chunk_data, 0)
            elif chunk_type == 'IEND':
                found_iend = True
            elif chunk_type in ('tEXt', 'zTXt', 'iTXt'):
                result.metadata.append(ImageMetadata("text", chunk_data))
            elif chunk_type == 'eXIf':
                result.has_exif = True
                result.metadata.append(ImageMetadata("exif", chunk_data))
            elif chunk_type == 'iCCP':
                result.color_profiles.append(ImageColorProfile("icc", chunk_data))
                
            offset += 8 + length + 4 # length, type, data, crc
            
        if found_iend and offset < len(data):
            result.trailers.append(ImageTrailer(offset, data[offset:]))
            
        return result

class JPEGParser(BaseImageParser):
    def parse(self, data: bytes) -> ImageParserResult:
        result = ImageParserResult(format="JPEG")
        if len(data) < 2 or data[:2] != b'\xff\xd8':
            result.is_valid = False
            return result
            
        offset = 2
        found_eoi = False
        
        while offset < len(data) - 1 and not found_eoi:
            if data[offset] != 0xff:
                result.is_valid = False
                break
                
            marker = data[offset+1]
            
            if marker == 0xd9: # EOI
                found_eoi = True
                offset += 2
                break
                
            if marker in (0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0x00, 0xff):
                # standalone markers or padded
                offset += 2
                continue
                
            if offset + 4 > len(data):
                break
                
            length = struct.unpack_from('>H', data, offset+2)[0]
            if length < 2 or offset + 2 + length > len(data):
                result.is_valid = False
                break
                
            segment_name = f"APP{marker-0xe0}" if 0xe0 <= marker <= 0xef else f"M{marker:02x}"
            segment_data = data[offset+4:offset+2+length]
            
            result.segments.append(ImageSegment(segment_name, length, offset, segment_data))
            
            if marker == 0xc0 or marker == 0xc2: # SOF0 / SOF2
                if length >= 8:
                    result.height, result.width = struct.unpack_from('>HH', segment_data, 1)
            elif marker == 0xe1: # APP1 (EXIF / XMP)
                if segment_data.startswith(b'Exif\x00\x00'):
                    result.has_exif = True
                    result.metadata.append(ImageMetadata("exif", segment_data))
                elif b'http://ns.adobe.com/xap/1.0/' in segment_data:
                    result.has_xmp = True
                    result.metadata.append(ImageMetadata("xmp", segment_data))
            elif marker == 0xe2: # APP2 (ICC)
                if segment_data.startswith(b'ICC_PROFILE\x00'):
                    result.color_profiles.append(ImageColorProfile("icc", segment_data))
            elif marker == 0xed: # APP13 (IPTC)
                result.has_iptc = True
                result.metadata.append(ImageMetadata("iptc", segment_data))
                
            offset += 2 + length
            
            if marker == 0xda: # SOS
                # Entropy-coded data follows SOS until next marker
                while offset < len(data) - 1:
                    if data[offset] == 0xff and data[offset+1] != 0x00 and not (0xd0 <= data[offset+1] <= 0xd7):
                        break
                    offset += 1
                    
        if found_eoi and offset < len(data):
            result.trailers.append(ImageTrailer(offset, data[offset:]))
            
        if not found_eoi:
            result.is_valid = False
            
        return result

class GIFParser(BaseImageParser):
    def parse(self, data: bytes) -> ImageParserResult:
        result = ImageParserResult(format="GIF")
        if len(data) < 13:
            result.is_valid = False
            return result
            
        header = data[:6]
        if header not in (b'GIF87a', b'GIF89a'):
            result.is_valid = False
            return result
            
        result.width, result.height = struct.unpack_from('<HH', data, 6)
        
        # very basic structural scan to find the trailer
        offset = 13
        gct_flag = data[10] & 0x80
        if gct_flag:
            gct_size = 2 ** ((data[10] & 0x07) + 1)
            offset += 3 * gct_size
            
        # scan for trailer \x3b
        idx = data.find(b'\x3b', offset)
        if idx != -1:
            trailer_offset = idx + 1
            if trailer_offset < len(data):
                result.trailers.append(ImageTrailer(trailer_offset, data[trailer_offset:]))
        else:
            result.is_valid = False
            
        return result

class BMPParser(BaseImageParser):
    def parse(self, data: bytes) -> ImageParserResult:
        result = ImageParserResult(format="BMP")
        if len(data) < 14 or data[:2] != b'BM':
            result.is_valid = False
            return result
            
        file_size, = struct.unpack_from('<I', data, 2)
        if len(data) >= 26:
            result.width, result.height = struct.unpack_from('<II', data, 18)
            
        if file_size < len(data):
            result.trailers.append(ImageTrailer(file_size, data[file_size:]))
            
        if file_size > len(data):
            result.is_valid = False
            
        return result

class TIFFParser(BaseImageParser):
    def parse(self, data: bytes) -> ImageParserResult:
        result = ImageParserResult(format="TIFF")
        if len(data) < 8:
            result.is_valid = False
            return result
            
        bo = data[:2]
        if bo not in (b'II', b'MM'):
            result.is_valid = False
            return result
            
        magic = struct.unpack_from('<H' if bo == b'II' else '>H', data, 2)[0]
        if magic != 42:
            result.is_valid = False
            return result
            
        # Trailing detection is hard for TIFF without a full IFD walk.
        # Just return valid for now if magic is correct.
        return result

class WebPParser(BaseImageParser):
    def parse(self, data: bytes) -> ImageParserResult:
        result = ImageParserResult(format="WebP")
        if len(data) < 12 or data[:4] != b'RIFF' or data[8:12] != b'WEBP':
            result.is_valid = False
            return result
            
        riff_size = struct.unpack_from('<I', data, 4)[0]
        total_size = riff_size + 8
        
        if total_size < len(data):
            result.trailers.append(ImageTrailer(total_size, data[total_size:]))
            
        return result

class ImageAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.metadata_extractor = MetadataExtractor()
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        self.logger = logger

    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        
        parser = self._get_parser(file_bytes)
        if not parser:
            return findings
            
        result = parser.parse(file_bytes)
        
        self.metadata_extractor.run(file_bytes, context)
        self.ioc_extractor.run(file_bytes, context)
        self.entropy_engine.run(file_bytes, context, profile_name="image_whole")
        
        if not result.is_valid:
            findings.append(Finding(
                technique_id="IMAGE_INVALID_STRUCTURE",
                severity=Severity.HIGH,
                description=f"Invalid or corrupted {result.format} structure",
                evidence_locator="headers",
                confidence=Confidence.HIGH
            ))
            context.mark_stage_incomplete("image_analysis")
        
        # Check trailers (appended payload)
        for trailer in result.trailers:
            findings.append(Finding(
                technique_id="IMAGE_APPENDED_DATA",
                severity=Severity.HIGH,
                description=f"Found {len(trailer.data)} bytes of appended data after logical EOF",
                evidence_locator=f"offset_{trailer.offset}",
                confidence=Confidence.HIGH
            ))
            
            # Analyze trailer
            self.entropy_engine.run(trailer.data, context, profile_name="image_trailer")
            self.ioc_extractor.run(trailer.data, context)
            
            mime, _ = self.magic_detector.identify(trailer.data[:2048])
            self._check_polyglot(mime, trailer.data, "trailer", findings)
            
            # Steganography heuristic: high entropy trailer
            entropy = self._calc_entropy(trailer.data)
            if entropy > 7.5:
                findings.append(Finding(
                    technique_id="IMAGE_STEGANOGRAPHY_HEURISTIC",
                    severity=Severity.MEDIUM,
                    description="High entropy appended data suggests encrypted or packed payload",
                    evidence_locator="trailer",
                    confidence=Confidence.LOW
                ))

        # Check metadata blobs for size/entropy/polyglots
        for meta in result.metadata + result.color_profiles:
            if len(meta.data) > 500 * 1024:
                findings.append(Finding(
                    technique_id="IMAGE_OVERSIZED_METADATA",
                    severity=Severity.MEDIUM,
                    description=f"Oversized metadata block ({meta.type})",
                    evidence_locator=meta.type,
                    confidence=Confidence.MEDIUM
                ))
            
            mime, _ = self.magic_detector.identify(meta.data[:2048])
            self._check_polyglot(mime, meta.data, f"metadata_{meta.type}", findings)
            
        # Heuristics for chunks
        if len(result.metadata) > 20:
            findings.append(Finding(
                technique_id="IMAGE_STEGANOGRAPHY_HEURISTIC",
                severity=Severity.LOW,
                description="Excessive number of metadata/text chunks",
                evidence_locator="chunks",
                confidence=Confidence.LOW
            ))

        context.mark_stage_complete("image_analysis")
        return findings

    def _get_parser(self, data: bytes) -> Optional[BaseImageParser]:
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            return PNGParser(self.logger)
        if data.startswith(b'\xff\xd8'):
            return JPEGParser(self.logger)
        if data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
            return GIFParser(self.logger)
        if data.startswith(b'BM'):
            return BMPParser(self.logger)
        if data.startswith(b'II*\x00') or data.startswith(b'MM\x00*'):
            return TIFFParser(self.logger)
        if data.startswith(b'RIFF') and data[8:12] == b'WEBP':
            return WebPParser(self.logger)
        return None

    def _check_polyglot(self, mime: str, data: bytes, locator: str, findings: List[Finding]):
        if mime == "application/zip" or data.startswith(b"PK\x03\x04"):
            findings.append(Finding("IMAGE_POLYGLOT_ZIP", Severity.CRITICAL, "Appended/Embedded ZIP archive found", locator, Confidence.HIGH))
        elif mime == "application/pdf" or data.startswith(b"%PDF-"):
            findings.append(Finding("IMAGE_POLYGLOT_PDF", Severity.CRITICAL, "Appended/Embedded PDF found", locator, Confidence.HIGH))
        elif mime == "application/x-dosexec" or data.startswith(b"MZ"):
            findings.append(Finding("IMAGE_POLYGLOT_PE", Severity.CRITICAL, "Appended/Embedded PE executable found", locator, Confidence.HIGH))
        elif mime == "application/x-executable" or data.startswith(b"\x7fELF"):
            findings.append(Finding("IMAGE_POLYGLOT_ELF", Severity.CRITICAL, "Appended/Embedded ELF executable found", locator, Confidence.HIGH))
        elif b"<!DOCTYPE html>" in data.lower() or b"<html>" in data.lower():
            findings.append(Finding("IMAGE_POLYGLOT_HTML", Severity.HIGH, "Appended/Embedded HTML payload found", locator, Confidence.HIGH))
        elif b"<?php" in data.lower() or b"eval(" in data.lower():
            findings.append(Finding("IMAGE_POLYGLOT_SCRIPT", Severity.HIGH, "Appended/Embedded Script found", locator, Confidence.HIGH))

    def _calc_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        entropy = 0
        size = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for count in counts:
            if count > 0:
                p_x = count / size
                entropy -= p_x * math.log2(p_x)
        return entropy
