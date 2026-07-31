import os
import io
import stat
import zipfile
import tarfile
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Dict, Any

from ..core.interfaces import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.models import Finding
from ..core.enums import Severity, Confidence
from ..core.exceptions import ATAEResourceExhaustionError, ATAEParserError, ATAESecurityError
from ..core.logger import get_atae_logger
from ..core.config import config
from ..triage.magic import MagicByteDetection, FallbackMagicProvider

logger = get_atae_logger("archive")

class ArchiveMember:
    def __init__(self, name: str, size: int, compressed_size: int, is_dir: bool, is_symlink: bool, is_encrypted: bool, is_special: bool = False):
        self.name = name
        self.size = size
        self.compressed_size = compressed_size
        self.is_dir = is_dir
        self.is_symlink = is_symlink
        self.is_encrypted = is_encrypted
        self.is_special = is_special

class BaseArchiveHandler(ABC):
    @abstractmethod
    def get_members(self) -> List[ArchiveMember]:
        pass
        
    @abstractmethod
    def extract_member(self, member_name: str, target_path: str):
        pass
        
    @abstractmethod
    def read_member_bytes(self, member_name: str, length: int) -> bytes:
        pass

    @abstractmethod
    def get_compressed_size(self) -> int:
        pass

class ZipArchiveHandler(BaseArchiveHandler):
    def __init__(self, data: bytes):
        self.data_len = len(data)
        try:
            self.zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise ATAEParserError(f"Invalid ZIP archive: {e}")
            
    def get_members(self) -> List[ArchiveMember]:
        members = []
        for info in self.zf.infolist():
            is_encrypted = bool(info.flag_bits & 0x1)
            is_symlink = (info.external_attr >> 16) & stat.S_IFLNK == stat.S_IFLNK
            members.append(ArchiveMember(
                name=info.filename,
                size=info.file_size,
                compressed_size=info.compress_size,
                is_dir=info.is_dir(),
                is_symlink=is_symlink,
                is_encrypted=is_encrypted,
                is_special=False
            ))
        return members
        
    def extract_member(self, member_name: str, target_path: str):
        with self.zf.open(member_name) as source, open(target_path, "wb") as target:
            import shutil
            shutil.copyfileobj(source, target)

    def read_member_bytes(self, member_name: str, length: int) -> bytes:
        try:
            with self.zf.open(member_name) as f:
                return f.read(length)
        except Exception:
            return b""
            
    def get_compressed_size(self) -> int:
        return self.data_len

class TarArchiveHandler(BaseArchiveHandler):
    def __init__(self, data: bytes):
        self.data_len = len(data)
        try:
            self.tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except tarfile.TarError as e:
            raise ATAEParserError(f"Invalid TAR archive: {e}")
            
    def get_members(self) -> List[ArchiveMember]:
        members = []
        for info in self.tf.getmembers():
            is_symlink = info.issym() or info.islnk()
            is_dir = info.isdir()
            is_regular = info.isreg()
            is_special = not (is_regular or is_dir or is_symlink)
            
            members.append(ArchiveMember(
                name=info.name,
                size=info.size,
                compressed_size=info.size, 
                is_dir=is_dir,
                is_symlink=is_symlink,
                is_encrypted=False,
                is_special=is_special
            ))
        return members
        
    def extract_member(self, member_name: str, target_path: str):
        member = self.tf.getmember(member_name)
        with self.tf.extractfile(member) as source, open(target_path, "wb") as target:
            if source:
                import shutil
                shutil.copyfileobj(source, target)

    def read_member_bytes(self, member_name: str, length: int) -> bytes:
        try:
            member = self.tf.getmember(member_name)
            if member.isreg():
                with self.tf.extractfile(member) as f:
                    if f: return f.read(length)
            return b""
        except Exception:
            return b""

    def get_compressed_size(self) -> int:
        return self.data_len

class ArchiveAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.suspicious_extensions = {
            "exe": "Executable", "dll": "Library", "bat": "Batch Script",
            "ps1": "PowerShell", "vbs": "VBScript", "js": "JavaScript",
            "docm": "Macro Office", "xlsm": "Macro Office", "pptm": "Macro Office",
            "wsf": "Windows Script", "sh": "Shell Script"
        }
        self.archive_extensions = {"zip", "tar", "gz", "bz2", "7z", "rar", "xz"}
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        self.max_files = 10000
        self.max_directories = 2000
        self.max_path_length = 255
        
    def _get_handler(self, file_bytes: bytes, context: AnalysisContext) -> BaseArchiveHandler:
        if file_bytes.startswith(b"PK\x03\x04"):
            return ZipArchiveHandler(file_bytes)
        try:
            return TarArchiveHandler(file_bytes)
        except ATAEParserError:
            pass
        raise ATAEParserError("Unsupported archive structure or corrupted archive")

    def _is_safe_path(self, workspace_path: str, member_name: str) -> bool:
        target_path = os.path.realpath(os.path.abspath(os.path.join(workspace_path, member_name)))
        return target_path.startswith(os.path.realpath(os.path.abspath(workspace_path)))

    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        
        try:
            handler = self._get_handler(file_bytes, context)
        except ATAEParserError as e:
            findings.append(Finding(
                technique_id="ARCHIVE_CORRUPTED_OR_UNSUPPORTED",
                severity=Severity.HIGH,
                description=str(e),
                evidence_locator="whole_file",
                confidence=Confidence.HIGH
            ))
            context.mark_stage_incomplete("archive_analysis")
            return findings

        if context.current_depth > config.max_nesting_depth:
            findings.append(Finding(
                technique_id="ARCHIVE_EXCESSIVE_NESTING",
                severity=Severity.CRITICAL,
                description=f"Archive exceeds maximum nesting depth of {config.max_nesting_depth}",
                evidence_locator="archive_depth",
                confidence=Confidence.HIGH
            ))
            return findings

        members = handler.get_members()
        
        total_uncompressed = 0
        total_compressed = handler.get_compressed_size()
        seen_names = set()
        
        extraction_plan = []
        file_count = 0
        dir_count = 0
        
        # 1. Inspection Phase
        for member in members:
            # Check length limit
            if len(member.name) > self.max_path_length:
                findings.append(Finding(
                    technique_id="ARCHIVE_EXCESSIVE_PATH_LENGTH",
                    severity=Severity.MEDIUM,
                    description=f"Member path exceeds limit: {len(member.name)} chars",
                    evidence_locator=member.name[:255] + "...",
                    confidence=Confidence.HIGH
                ))
                continue

            if member.is_dir:
                dir_count += 1
                if dir_count > self.max_directories:
                    findings.append(Finding(
                        technique_id="ARCHIVE_QUOTA_EXCEEDED",
                        severity=Severity.CRITICAL,
                        description="Maximum directory quota exceeded",
                        evidence_locator="directory_limit",
                        confidence=Confidence.HIGH
                    ))
                    return findings
            else:
                file_count += 1
                if file_count > self.max_files:
                    findings.append(Finding(
                        technique_id="ARCHIVE_QUOTA_EXCEEDED",
                        severity=Severity.CRITICAL,
                        description="Maximum file quota exceeded",
                        evidence_locator="file_limit",
                        confidence=Confidence.HIGH
                    ))
                    return findings

            # Zip Slip / Path Traversal Validation (Inspection phase)
            if not self._is_safe_path(context.workspace_path or "/tmp/atae_fallback", member.name):
                findings.append(Finding(
                    technique_id="ARCHIVE_PATH_TRAVERSAL",
                    severity=Severity.CRITICAL,
                    description=f"Attempted path traversal (Zip Slip) detected: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))
                continue
                
            # Symlinks
            if member.is_symlink:
                findings.append(Finding(
                    technique_id="ARCHIVE_SYMLINK",
                    severity=Severity.HIGH,
                    description=f"Symlink found inside archive: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))
                continue
                
            # Special devices
            if member.is_special:
                findings.append(Finding(
                    technique_id="ARCHIVE_SPECIAL_ENTRY",
                    severity=Severity.HIGH,
                    description=f"Special/Device entry found: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))
                continue

            # Duplicate filenames
            normalized = os.path.normpath(member.name).lower()
            if normalized in seen_names and not member.is_dir:
                findings.append(Finding(
                    technique_id="ARCHIVE_DUPLICATE_FILENAME",
                    severity=Severity.MEDIUM,
                    description=f"Duplicate filename found: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))
            seen_names.add(normalized)

            # Hidden files
            basename = os.path.basename(member.name)
            if basename.startswith('.'):
                findings.append(Finding(
                    technique_id="ARCHIVE_HIDDEN_FILE",
                    severity=Severity.LOW,
                    description=f"Hidden file detected: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))

            # Encrypted handling
            if member.is_encrypted:
                findings.append(Finding(
                    technique_id="ARCHIVE_ENCRYPTED_MEMBER",
                    severity=Severity.HIGH,
                    description=f"Encrypted member found: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))
                continue

            # Suspicious Extensions & Nested Archives
            ext = member.name.split('.')[-1].lower() if '.' in member.name else ""
            if ext in self.suspicious_extensions:
                file_type = self.suspicious_extensions[ext]
                findings.append(Finding(
                    technique_id="ARCHIVE_SUSPICIOUS_CONTENT",
                    severity=Severity.HIGH,
                    description=f"{file_type} found inside archive: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))
            elif ext in self.archive_extensions:
                findings.append(Finding(
                    technique_id="ARCHIVE_NESTED",
                    severity=Severity.MEDIUM,
                    description=f"Nested archive found: {member.name}",
                    evidence_locator=member.name,
                    confidence=Confidence.HIGH
                ))

            # Magic Byte Detection
            if not member.is_dir and member.size > 0:
                head = handler.read_member_bytes(member.name, 2048)
                mime, desc = self.magic_detector.identify(head)
                if mime == "application/x-dosexec":
                    findings.append(Finding(
                        technique_id="ARCHIVE_MAGIC_EXECUTABLE",
                        severity=Severity.HIGH,
                        description=f"File matching Executable magic bytes found: {member.name}",
                        evidence_locator=member.name,
                        confidence=Confidence.HIGH
                    ))

            # Member-level Compression Ratio Check
            if member.compressed_size > 0 and member.size > 0:
                ratio = member.size / member.compressed_size
                if ratio > config.max_compression_ratio:
                    findings.append(Finding(
                        technique_id="ARCHIVE_MEMBER_BOMB_RATIO",
                        severity=Severity.CRITICAL,
                        description=f"Member {member.name} compression ratio {ratio:.1f}x exceeds limit",
                        evidence_locator=member.name,
                        confidence=Confidence.HIGH
                    ))
                    continue

            total_uncompressed += member.size
            if not member.is_dir:
                extraction_plan.append(member)

        # Archive-level Limits (Compression Ratio / Bombs)
        try:
            context.check_limits(added_size=total_uncompressed)
        except ATAEResourceExhaustionError as e:
            findings.append(Finding(
                technique_id="ARCHIVE_BOMB",
                severity=Severity.CRITICAL,
                description=str(e),
                evidence_locator="size_limits",
                confidence=Confidence.HIGH
            ))
            return findings

        if total_compressed > 0 and total_uncompressed > 0:
            ratio = total_uncompressed / total_compressed
            if ratio > config.max_compression_ratio:
                findings.append(Finding(
                    technique_id="ARCHIVE_BOMB_RATIO",
                    severity=Severity.CRITICAL,
                    description=f"Total compression ratio {ratio:.1f}x exceeds limit",
                    evidence_locator="total_compression_ratio",
                    confidence=Confidence.HIGH
                ))
                return findings

        # 2. Validation and Extraction Phase
        if context.workspace_path:
            extract_dir = os.path.join(context.workspace_path, f"extracted_depth_{context.current_depth}")
            os.makedirs(extract_dir, exist_ok=True)
            
            for member in extraction_plan:
                # TOCTOU Mitigation
                target_file = os.path.realpath(os.path.abspath(os.path.join(extract_dir, member.name)))
                if not target_file.startswith(os.path.realpath(os.path.abspath(extract_dir))):
                    findings.append(Finding(
                        technique_id="ARCHIVE_PATH_TRAVERSAL_EXTRACTION",
                        severity=Severity.CRITICAL,
                        description=f"Path traversal detected during extraction: {member.name}",
                        evidence_locator=member.name,
                        confidence=Confidence.HIGH
                    ))
                    continue
                    
                os.makedirs(os.path.dirname(target_file), exist_ok=True)
                try:
                    handler.extract_member(member.name, target_file)
                except Exception as e:
                    logger.error(f"Failed to extract {member.name}: {e}")

        context.mark_stage_complete("archive_analysis")
        return findings
