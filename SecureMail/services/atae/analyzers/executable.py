import struct
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

logger = get_atae_logger("executable")

@dataclass
class ExecutableSection:
    name: str
    size: int
    entropy: float
    is_rwx: bool
    is_executable: bool
    data: bytes

@dataclass
class ExecutableImport:
    dll: str
    function: str

@dataclass
class ExecutableParserResult:
    format_name: str
    is_valid: bool = True
    sections: List[ExecutableSection] = field(default_factory=list)
    imports: List[ExecutableImport] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    has_overlay: bool = False
    has_debug: bool = False
    has_authenticode: bool = False
    timestamp: int = 0
    pdb_path: Optional[str] = None
    version_info: Dict[str, str] = field(default_factory=dict)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

import math

def calc_entropy(data: bytes) -> float:
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

class BaseExecutableParser(ABC):
    def __init__(self, parser_logger):
        self.logger = parser_logger
        
    @abstractmethod
    def parse(self, data: bytes) -> ExecutableParserResult:
        pass

class PEParser(BaseExecutableParser):
    def parse(self, data: bytes) -> ExecutableParserResult:
        result = ExecutableParserResult(format_name="PE")
        if len(data) < 64:
            result.is_valid = False; return result
            
        if data[:2] != b"MZ":
            result.is_valid = False; return result
            
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            result.is_valid = False; return result
            
        if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            result.is_valid = False; return result
            
        # FileHeader
        fh_offset = e_lfanew + 4
        num_sections, timestamp, size_opt_hdr = struct.unpack_from('<H I 8x H 2x', data, fh_offset)
        result.timestamp = timestamp
        
        opt_hdr_offset = fh_offset + 20
        if opt_hdr_offset + size_opt_hdr > len(data):
            result.is_valid = False; return result
            
        magic = struct.unpack_from('<H', data, opt_hdr_offset)[0]
        if magic == 0x10B: # PE32
            dd_offset = opt_hdr_offset + 96
        elif magic == 0x20B: # PE32+
            dd_offset = opt_hdr_offset + 112
        else:
            result.is_valid = False; return result
            
        def get_dd(index):
            off = dd_offset + index * 8
            if off + 8 <= opt_hdr_offset + size_opt_hdr:
                return struct.unpack_from('<I I', data, off)
            return 0, 0
            
        imp_rva, imp_size = get_dd(1)
        sec_rva, sec_size = get_dd(4)
        dbg_rva, dbg_size = get_dd(6)
        
        if sec_rva > 0 and sec_size > 0:
            result.has_authenticode = True
            
        sections_offset = opt_hdr_offset + size_opt_hdr
        max_ptr = 0
        
        def rva_to_offset(rva):
            for sec in result.sections:
                if sec.raw_metadata.get('vaddr', 0) <= rva < sec.raw_metadata.get('vaddr', 0) + sec.raw_metadata.get('vsize', 0):
                    return rva - sec.raw_metadata['vaddr'] + sec.raw_metadata['raw_ptr']
            return 0

        for i in range(num_sections):
            sec_off = sections_offset + i * 40
            if sec_off + 40 > len(data):
                break
            name, vsize, vaddr, raw_size, raw_ptr, _, _, _, _, chars = struct.unpack_from('<8s I I I I I I H H I', data, sec_off)
            
            clean_name = name.split(b'\x00')[0].decode('utf-8', errors='ignore')
            
            is_exec = (chars & 0x20000000) != 0
            is_read = (chars & 0x40000000) != 0
            is_write = (chars & 0x80000000) != 0
            is_rwx = is_exec and is_read and is_write
            
            sec_data = data[raw_ptr:raw_ptr + raw_size]
            entropy = calc_entropy(sec_data)
            
            sec_obj = ExecutableSection(clean_name, raw_size, entropy, is_rwx, is_exec, sec_data)
            sec_obj.raw_metadata = {'vaddr': vaddr, 'vsize': vsize, 'raw_ptr': raw_ptr}
            result.sections.append(sec_obj)
            
            if raw_ptr + raw_size > max_ptr:
                max_ptr = raw_ptr + raw_size
                
        if sec_rva > 0 and sec_size > 0:
            if sec_rva + sec_size > max_ptr:
                max_ptr = sec_rva + sec_size
        
        if max_ptr > 0 and max_ptr < len(data):
            result.has_overlay = True
            
        if dbg_rva > 0 and dbg_size >= 28:
            dbg_off = rva_to_offset(dbg_rva)
            if dbg_off > 0 and dbg_off + 28 <= len(data):
                result.has_debug = True
                cv_type, cv_ptr = struct.unpack_from('<I 16x I', data, dbg_off + 4)
                if cv_type == 2:
                    cv_off = rva_to_offset(cv_ptr)
                    if cv_off > 0 and cv_off + 4 <= len(data):
                        cv_sig = data[cv_off:cv_off+4]
                        if cv_sig == b'RSDS':
                            pdb_start = cv_off + 24
                            pdb_end = data.find(b'\x00', pdb_start)
                            if pdb_end != -1:
                                result.pdb_path = data[pdb_start:pdb_end].decode('utf-8', errors='ignore')
                                
        if imp_rva > 0 and imp_size > 0:
            imp_off = rva_to_offset(imp_rva)
            while imp_off > 0 and imp_off + 20 <= len(data):
                ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from('<I I I I I', data, imp_off)
                if ilt_rva == 0 and name_rva == 0:
                    break
                    
                dll_name_off = rva_to_offset(name_rva)
                dll_name = ""
                if dll_name_off > 0:
                    dll_end = data.find(b'\x00', dll_name_off)
                    if dll_end != -1:
                        dll_name = data[dll_name_off:dll_end].decode('utf-8', errors='ignore')
                
                thunk_rva = ilt_rva if ilt_rva > 0 else iat_rva
                thunk_off = rva_to_offset(thunk_rva)
                pointer_size = 4 if magic == 0x10B else 8
                
                while thunk_off > 0 and thunk_off + pointer_size <= len(data):
                    if pointer_size == 4:
                        val = struct.unpack_from('<I', data, thunk_off)[0]
                        ordinal_flag = 0x80000000
                    else:
                        val = struct.unpack_from('<Q', data, thunk_off)[0]
                        ordinal_flag = 0x8000000000000000
                        
                    if val == 0:
                        break
                        
                    if not (val & ordinal_flag):
                        func_name_off = rva_to_offset(val & ~ordinal_flag)
                        if func_name_off > 0 and func_name_off + 2 <= len(data):
                            func_end = data.find(b'\x00', func_name_off + 2)
                            if func_end != -1:
                                func_name = data[func_name_off+2:func_end].decode('utf-8', errors='ignore')
                                result.imports.append(ExecutableImport(dll_name, func_name))
                                
                    thunk_off += pointer_size
                imp_off += 20
                
        rsrc = next((s for s in result.sections if s.name == ".rsrc"), None)
        if rsrc:
            idx = rsrc.data.find(b"V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00")
            if idx != -1:
                result.version_info["VS_VERSION_INFO"] = "Present"

        return result

class ELFParser(BaseExecutableParser):
    def parse(self, data: bytes) -> ExecutableParserResult:
        result = ExecutableParserResult(format_name="ELF")
        if len(data) < 4 or data[:4] != b"\x7fELF":
            result.is_valid = False
            return result
            
        if b".debug_info" in data:
            result.has_debug = True
            
        if b"ptrace" in data:
            result.imports.append(ExecutableImport("libc.so", "ptrace"))
            
        return result

class MachOParser(BaseExecutableParser):
    def parse(self, data: bytes) -> ExecutableParserResult:
        result = ExecutableParserResult(format_name="Mach-O")
        # Magic bytes: FEEDFACE, FEEDFACF, CAFEBABE, CAFEBABF
        if len(data) < 4:
            result.is_valid = False
            return result
            
        magic = data[:4]
        if magic not in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            result.is_valid = False
            return result
            
        return result

class ExecutableAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.metadata_extractor = MetadataExtractor()
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        self.logger = logger
        
        self.suspicious_imports = {
            "virtualalloc", "virtualprotect", "createremotethread", 
            "writeprocessmemory", "loadlibrary", "getprocaddress",
            "ptrace", "system", "winexec", "shellexecute"
        }
        
        self.suspicious_sections = {
            ".upx", ".vmp", ".aspack", ".pespin", ".themida"
        }

    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        
        if len(file_bytes) < 4:
            raise ATAEParserError("File too small")
            
        magic = file_bytes[:4]
        if magic.startswith(b"MZ"):
            parser = PEParser(self.logger)
        elif magic.startswith(b"\x7fELF"):
            parser = ELFParser(self.logger)
        elif magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            parser = MachOParser(self.logger)
        else:
            raise ATAEParserError("Not a recognized executable format")
            
        result = parser.parse(file_bytes)
        
        self.metadata_extractor.run(file_bytes, context)
        self.ioc_extractor.run(file_bytes, context)
        self.entropy_engine.run(file_bytes, context, profile_name="executable_whole")
        
        if not result.is_valid:
            findings.append(Finding(
                technique_id="EXEC_INVALID_HEADER",
                severity=Severity.HIGH,
                description=f"Invalid or corrupted {result.format_name} headers",
                evidence_locator="header",
                confidence=Confidence.HIGH
            ))
            context.mark_stage_incomplete("executable_analysis")
            return findings

        if result.has_overlay:
            findings.append(Finding(
                technique_id="EXEC_OVERLAY_DATA",
                severity=Severity.MEDIUM,
                description="Overlay data appended to the executable",
                evidence_locator="EOF",
                confidence=Confidence.HIGH
            ))
            
        if result.has_debug:
            findings.append(Finding(
                technique_id="EXEC_DEBUG_INFO",
                severity=Severity.LOW,
                description="Debug information present",
                evidence_locator="PDB/RSDS",
                confidence=Confidence.HIGH
            ))
            
        if result.has_authenticode:
            findings.append(Finding(
                technique_id="EXEC_AUTHENTICODE",
                severity=Severity.INFO,
                description="Digital signature present",
                evidence_locator="authenticode",
                confidence=Confidence.HIGH
            ))
            
        for imp in result.imports:
            if imp.function.lower() in self.suspicious_imports:
                findings.append(Finding(
                    technique_id="EXEC_SUSPICIOUS_IMPORT",
                    severity=Severity.HIGH,
                    description=f"Suspicious API import: {imp.function}",
                    evidence_locator=f"{imp.dll}!{imp.function}",
                    confidence=Confidence.HIGH
                ))
                
        is_packed = False
        for sec in result.sections:
            sec_name_lower = sec.name.lower()
            
            for susp in self.suspicious_sections:
                if susp in sec_name_lower:
                    is_packed = True
                    findings.append(Finding(
                        technique_id="EXEC_SUSPICIOUS_SECTION",
                        severity=Severity.HIGH,
                        description=f"Suspicious section name indicative of packer: {sec.name}",
                        evidence_locator=sec.name,
                        confidence=Confidence.HIGH
                    ))
                    
            if sec.entropy > 7.2:
                is_packed = True
                findings.append(Finding(
                    technique_id="EXEC_HIGH_ENTROPY_SECTION",
                    severity=Severity.MEDIUM,
                    description=f"High entropy ({sec.entropy:.2f}) in section {sec.name}",
                    evidence_locator=sec.name,
                    confidence=Confidence.HIGH
                ))
                
            if sec.is_rwx:
                findings.append(Finding(
                    technique_id="EXEC_RWX_SECTION",
                    severity=Severity.CRITICAL,
                    description=f"RWX (Read-Write-Execute) section found: {sec.name}",
                    evidence_locator=sec.name,
                    confidence=Confidence.HIGH
                ))
                
            if sec_name_lower == ".rsrc" and sec.is_executable:
                findings.append(Finding(
                    technique_id="EXEC_EXECUTABLE_RESOURCE",
                    severity=Severity.CRITICAL,
                    description="Executable code found in resource section",
                    evidence_locator=sec.name,
                    confidence=Confidence.HIGH
                ))

        if is_packed:
            findings.append(Finding(
                technique_id="EXEC_PACKED",
                severity=Severity.HIGH,
                description="Executable exhibits signs of packing or obfuscation",
                evidence_locator="sections",
                confidence=Confidence.HIGH
            ))
            
        context.mark_stage_complete("executable_analysis")
        return findings
