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

logger = get_atae_logger("script")

@dataclass
class ScriptCommand:
    command: str
    arguments: List[str] = field(default_factory=list)

@dataclass
class ScriptString:
    value: str
    is_encoded: bool = False

@dataclass
class ScriptURL:
    url: str

@dataclass
class ScriptIOC:
    type: str
    value: str

@dataclass
class ScriptFunction:
    name: str

@dataclass
class ScriptVariable:
    name: str

@dataclass
class ScriptEncoding:
    type: str
    decoded_value: bytes

@dataclass
class ScriptParserResult:
    language: str
    commands: List[ScriptCommand] = field(default_factory=list)
    functions: List[ScriptFunction] = field(default_factory=list)
    variables: List[ScriptVariable] = field(default_factory=list)
    strings: List[ScriptString] = field(default_factory=list)
    urls: List[ScriptURL] = field(default_factory=list)
    encodings: List[ScriptEncoding] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    suspicious_tokens: List[str] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

class BaseScriptParser(ABC):
    def __init__(self, parser_logger):
        self.logger = parser_logger
        self.b64_regex = re.compile(rb'(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        self.hex_regex = re.compile(rb'(?:0x)?[0-9a-fA-F]{40,}')

    def extract_encodings(self, data: bytes, result: ScriptParserResult) -> str:
        for b64 in self.b64_regex.finditer(data):
            try:
                decoded = base64.b64decode(b64.group())
                result.encodings.append(ScriptEncoding("base64", decoded))
            except Exception as e:
                pass
                
        for hx in self.hex_regex.finditer(data):
            match = hx.group()
            if match.startswith(b"0x"):
                match = match[2:]
            try:
                decoded = binascii.unhexlify(match)
                result.encodings.append(ScriptEncoding("hex", decoded))
            except Exception as e:
                pass
                
        decoded_content = data.decode('utf-8', errors='ignore').lower()
        for enc in result.encodings:
            decoded_content += " " + enc.decoded_value.decode('utf-8', errors='ignore').lower()
        return decoded_content

    @abstractmethod
    def parse(self, data: bytes) -> ScriptParserResult:
        pass

class PowerShellParser(BaseScriptParser):
    def parse(self, data: bytes) -> ScriptParserResult:
        result = ScriptParserResult(language="PowerShell")
        content = self.extract_encodings(data, result)
        
        cmd_regex = re.compile(r'\b([A-Za-z]+-[A-Za-z]+)\b')
        for cmd in cmd_regex.findall(content):
            result.commands.append(ScriptCommand(cmd))
            
        for token in ["iex", "encodedcommand", "downloadstring", "downloadfile", "downloaddata", 
                     "webclient", "amsiutils", "bypass", "invoke-expression"]:
            if token in content:
                result.suspicious_tokens.append(token)
                
        if b'\x00' in data:
            result.raw_metadata['has_null_bytes'] = True
            
        return result

class JavaScriptParser(BaseScriptParser):
    def parse(self, data: bytes) -> ScriptParserResult:
        result = ScriptParserResult(language="JavaScript")
        content = self.extract_encodings(data, result)
        
        for token in ["eval", "function(", "settimeout", "setinterval", "document.write", 
                     "xmlhttprequest", "fetch", "activexobject", "wscript.shell", "shell.application"]:
            if token in content:
                result.suspicious_tokens.append(token)
                
        return result

class VBScriptParser(BaseScriptParser):
    def parse(self, data: bytes) -> ScriptParserResult:
        result = ScriptParserResult(language="VBScript")
        content = self.extract_encodings(data, result)
        
        for token in ["createobject", "getobject", "wscript.shell", "shell.application", "run", 
                     "exec", "execute", "executeglobal", "eval", "adodb.stream", "xmlhttp", "msxml2.xmlhttp", "winhttp"]:
            if token in content:
                result.suspicious_tokens.append(token)
                
        return result

class BatchParser(BaseScriptParser):
    def parse(self, data: bytes) -> ScriptParserResult:
        result = ScriptParserResult(language="Batch")
        content = self.extract_encodings(data, result)
        
        for token in ["powershell", "certutil", "bitsadmin", "curl", "wget", "mshta", 
                     "regsvr32", "rundll32", "wmic", "schtasks", "at", "reg"]:
            if token in content:
                result.suspicious_tokens.append(token)
                
        return result

class ShellParser(BaseScriptParser):
    def parse(self, data: bytes) -> ScriptParserResult:
        result = ScriptParserResult(language="Shell")
        content = self.extract_encodings(data, result)
        
        for token in ["curl", "wget", "nc", "bash", "chmod", "mktemp", 
                     "openssl", "python", "perl", "eval", "nohup", "systemctl"]:
            if token in content:
                result.suspicious_tokens.append(token)
                
        return result

class PythonParser(BaseScriptParser):
    def parse(self, data: bytes) -> ScriptParserResult:
        result = ScriptParserResult(language="Python")
        content = self.extract_encodings(data, result)
        
        for token in ["exec", "eval", "compile", "marshal", "pickle", "base64", "zlib", 
                     "subprocess", "os.system", "popen", "socket", "requests", "urllib", "ctypes", "execfile"]:
            if token in content:
                result.suspicious_tokens.append(token)
                
        return result

class ScriptAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.metadata_extractor = MetadataExtractor()
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        self.logger = logger
        
        self.analyzers_map = {
            "PowerShell": self._evaluate_powershell,
            "JavaScript": self._evaluate_javascript,
            "VBScript": self._evaluate_vbscript,
            "Batch": self._evaluate_batch,
            "Shell": self._evaluate_shell,
            "Python": self._evaluate_python
        }

    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        findings = []
        
        parser = self._get_parser(context.declared_filename, file_bytes)
        if not parser:
            return []
            
        result = parser.parse(file_bytes)
        
        self.metadata_extractor.run(file_bytes, context)
        self.ioc_extractor.run(file_bytes, context)
        self.entropy_engine.run(file_bytes, context, profile_name="script_whole")
        
        # Obfuscation checks
        if len(result.encodings) > 0:
            findings.append(Finding(
                technique_id="SCRIPT_OBFUSCATION",
                severity=Severity.HIGH,
                description=f"Script contains {len(result.encodings)} encoded blobs",
                evidence_locator="encodings",
                confidence=Confidence.HIGH
            ))
            
            for i, enc in enumerate(result.encodings):
                self.entropy_engine.run(enc.decoded_value, context, profile_name=f"script_encoded_{i}")
                self.ioc_extractor.run(enc.decoded_value, context)
                
                mime, _ = self.magic_detector.identify(enc.decoded_value[:2048])
                if mime == "application/x-dosexec" or enc.decoded_value.startswith(b"MZ"):
                    findings.append(Finding(
                        technique_id="SCRIPT_EMBEDDED_EXECUTABLE",
                        severity=Severity.CRITICAL,
                        description="Decoded payload contains embedded PE executable",
                        evidence_locator=f"encoding_{i}",
                        confidence=Confidence.HIGH
                    ))
                elif enc.decoded_value.startswith(b"PK\x03\x04"):
                    findings.append(Finding(
                        technique_id="SCRIPT_EMBEDDED_ARCHIVE",
                        severity=Severity.MEDIUM,
                        description="Decoded payload contains ZIP archive",
                        evidence_locator=f"encoding_{i}",
                        confidence=Confidence.HIGH
                    ))

        # Language specific evaluation
        eval_func = self.analyzers_map.get(result.language)
        if eval_func:
            findings.extend(eval_func(result))
            
        context.mark_stage_complete("script_analysis")
        return findings

    def _get_parser(self, filename: str, data: bytes) -> Optional[BaseScriptParser]:
        name = (filename or "").lower()
        if name.endswith((".ps1", ".psm1", ".psd1")):
            return PowerShellParser(self.logger)
        elif name.endswith(".js"):
            return JavaScriptParser(self.logger)
        elif name.endswith(".vbs"):
            return VBScriptParser(self.logger)
        elif name.endswith((".bat", ".cmd")):
            return BatchParser(self.logger)
        elif name.endswith(".sh"):
            return ShellParser(self.logger)
        elif name.endswith(".py"):
            return PythonParser(self.logger)
            
        # Magic-based fallback
        if data.startswith(b"#!/bin/bash") or data.startswith(b"#!/bin/sh"):
            return ShellParser(self.logger)
        if data.startswith(b"#!/usr/bin/env python") or data.startswith(b"#!/usr/bin/python"):
            return PythonParser(self.logger)
            
        return None
        
    def _evaluate_powershell(self, result: ScriptParserResult) -> List[Finding]:
        findings = []
        for cmd in result.commands:
            if cmd.command in ["invoke-expression", "invoke-command", "start-process"]:
                findings.append(Finding("PS_EXECUTION", Severity.HIGH, f"Dynamic execution: {cmd.command}", cmd.command, Confidence.HIGH))
            elif cmd.command in ["invoke-webrequest", "start-bitstransfer"]:
                findings.append(Finding("PS_DOWNLOAD", Severity.HIGH, f"File download: {cmd.command}", cmd.command, Confidence.HIGH))
                
        for token in result.suspicious_tokens:
            if token == "iex":
                findings.append(Finding("PS_IEX", Severity.HIGH, "Invoke-Expression alias used", token, Confidence.HIGH))
            elif token == "amsiutils":
                findings.append(Finding("PS_AMSI_BYPASS", Severity.CRITICAL, "AMSI bypass indicator", token, Confidence.HIGH))
            elif token in ["encodedcommand", "bypass"]:
                findings.append(Finding("PS_OBFUSCATION", Severity.HIGH, f"Suspicious parameter: {token}", token, Confidence.HIGH))
        return findings

    def _evaluate_javascript(self, result: ScriptParserResult) -> List[Finding]:
        findings = []
        for token in result.suspicious_tokens:
            if token in ["eval", "function", "settimeout", "setinterval"]:
                findings.append(Finding("JS_DYNAMIC_EXECUTION", Severity.HIGH, f"Dynamic execution: {token}", token, Confidence.HIGH))
            elif token in ["activexobject", "wscript.shell", "shell.application"]:
                findings.append(Finding("JS_WSH", Severity.CRITICAL, f"Windows Scripting Host execution: {token}", token, Confidence.HIGH))
        return findings

    def _evaluate_vbscript(self, result: ScriptParserResult) -> List[Finding]:
        findings = []
        for token in result.suspicious_tokens:
            if token in ["createobject", "getobject", "wscript.shell", "shell.application", "run", "exec", "execute"]:
                findings.append(Finding("VBS_EXECUTION", Severity.CRITICAL, f"VBS execution/object creation: {token}", token, Confidence.HIGH))
        return findings

    def _evaluate_batch(self, result: ScriptParserResult) -> List[Finding]:
        findings = []
        for token in result.suspicious_tokens:
            if token == "powershell":
                findings.append(Finding("BAT_POWERSHELL", Severity.HIGH, "PowerShell invocation from batch", token, Confidence.HIGH))
            elif token in ["certutil", "bitsadmin"]:
                findings.append(Finding("BAT_DOWNLOAD", Severity.HIGH, f"Living-off-the-land download: {token}", token, Confidence.HIGH))
        return findings

    def _evaluate_shell(self, result: ScriptParserResult) -> List[Finding]:
        findings = []
        for token in result.suspicious_tokens:
            if token in ["curl", "wget", "nc"]:
                findings.append(Finding("SH_NETWORK", Severity.HIGH, f"Network utility used: {token}", token, Confidence.HIGH))
            elif token in ["bash", "eval", "python"]:
                findings.append(Finding("SH_EXECUTION", Severity.MEDIUM, f"Execution/Interpreter: {token}", token, Confidence.HIGH))
        return findings

    def _evaluate_python(self, result: ScriptParserResult) -> List[Finding]:
        findings = []
        for token in result.suspicious_tokens:
            if token in ["exec", "eval", "compile"]:
                findings.append(Finding("PY_DYNAMIC_EXECUTION", Severity.HIGH, f"Dynamic execution: {token}", token, Confidence.HIGH))
            elif token in ["subprocess", "os.system", "popen"]:
                findings.append(Finding("PY_SUBPROCESS", Severity.HIGH, f"OS command execution: {token}", token, Confidence.HIGH))
        return findings
