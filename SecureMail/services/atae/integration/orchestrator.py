import time
import hashlib
from typing import Optional, List, Dict
from ..core.context import AnalysisContext
from ..core.registry import AnalyzerRegistry, AnalyzerRegistration
from ..core.logger import get_atae_logger
from ..core.exceptions import ATAEParserError
from ..core.models import Finding
from ..services.metadata import MetadataExtractor
from ..services.ioc import IOCExtractor
from ..services.entropy import EntropyEngine
from ..services.risk import RiskScoringEngine
from ..triage.magic import MagicByteDetection, FallbackMagicProvider
from .models import AnalysisResult, AnalysisReport

logger = get_atae_logger("orchestrator")

class AnalyzerSelector:
    def __init__(self, magic_detector: MagicByteDetection):
        self.magic_detector = magic_detector

    def select(self, file_bytes: bytes, filename: str, declared_mime: str) -> Optional[AnalyzerRegistration]:
        # 1. Magic bytes
        magic_mime, magic_name = self.magic_detector.identify(file_bytes[:2048])
        
        # 2. Extract Extension
        ext = ""
        if filename and '.' in filename:
            ext = filename.rsplit('.', 1)[-1].lower()

        candidates = AnalyzerRegistry.get_all()
        
        # First priority: Magic match
        for reg in candidates:
            if not reg.is_fallback:
                if magic_mime in reg.mimes or magic_name in reg.magics:
                    return reg
                    
        # Second priority: Declared MIME + Extension
        for reg in candidates:
            if not reg.is_fallback:
                if declared_mime in reg.mimes and ext in reg.extensions:
                    return reg

        # Third priority: Extension only if magic couldn't identify it as something else strongly
        # "Never extension alone." so if magic is known to be something else, we don't route.
        # If magic is generic octet-stream, we can use extension.
        if magic_mime == "application/octet-stream":
            for reg in candidates:
                if not reg.is_fallback:
                    if ext in reg.extensions:
                        return reg

        # Fallback
        for reg in candidates:
            if reg.is_fallback:
                return reg
                
        return None

class FindingCorrelator:
    def correlate(self, findings: List[Finding]) -> List[Finding]:
        unique_map = {}
        for f in findings:
            key = (f.technique_id, f.evidence_locator)
            if key not in unique_map:
                unique_map[key] = f
                
        correlated = list(unique_map.values())
        
        # Aggregate correlated logic
        has_zip = any("ZIP" in f.description for f in correlated)
        has_pe = any("PE" in f.description for f in correlated)
        
        if has_zip and has_pe:
            from ..core.enums import Severity, Confidence
            correlated.append(Finding(
                technique_id="CORRELATED_EMBEDDED_ZIP_PE",
                severity=Severity.CRITICAL,
                description="Nested embedded ZIP containing PE executable found",
                evidence_locator="correlation",
                confidence=Confidence.HIGH
            ))
            
        return correlated

class AnalysisPipeline:
    def __init__(self):
        self.magic_detector = MagicByteDetection(FallbackMagicProvider())
        self.selector = AnalyzerSelector(self.magic_detector)
        self.metadata_extractor = MetadataExtractor()
        self.ioc_extractor = IOCExtractor()
        self.entropy_engine = EntropyEngine()
        self.risk_engine = RiskScoringEngine()
        self.correlator = FindingCorrelator()
        self.logger = logger
        
    def execute(self, analysis_id: str, file_bytes: bytes, filename: str, declared_mime: str) -> AnalysisReport:
        start_time = time.time()
        report = AnalysisReport(
            analysis_id=analysis_id,
            file_name=filename,
            file_size=len(file_bytes),
            true_mime_type="unknown"
        )
        
        try:
            ctx = AnalysisContext(analysis_id, "", filename, declared_mime)
            
            # Hash calculation
            report.hashes['md5'] = hashlib.md5(file_bytes).hexdigest()
            report.hashes['sha256'] = hashlib.sha256(file_bytes).hexdigest()
            
            # Metadata & Magic
            self.metadata_extractor.run(file_bytes, ctx)
            magic_mime, _ = self.magic_detector.identify(file_bytes[:2048])
            ctx.true_mime_type = magic_mime
            report.true_mime_type = magic_mime
            
            # Analyzer Selection
            selected_reg = self.selector.select(file_bytes, filename, declared_mime)
            if not selected_reg:
                report.errors.append("No analyzer found, and no fallback available.")
                return report
                
            report.analyzer_used = selected_reg.name
            analyzer_instance = selected_reg.analyzer_cls()
            
            # Execute selected analyzer
            try:
                findings = analyzer_instance.analyze(file_bytes, ctx)
                ctx.findings.extend(findings)
            except Exception as e:
                report.errors.append(f"Parser error in {selected_reg.name}: {str(e)}")
                self.logger.error(f"Analyzer failed: {e}")
                
            # Correlate
            correlated_findings = self.correlator.correlate(ctx.findings)
            report.findings = correlated_findings
            
            # 5. Risk Scoring
            verdict = self.risk_engine.evaluate(analysis_id, report.findings)
            report.risk_score = verdict.risk_score
            report.risk_level = verdict.band.name
            
            # 6. Summary (Populate report)           # Note: The analyzers already called ioc/entropy/metadata extractors on relevant parts.
            report.iocs = ctx.iocs
            report.metadata = ctx.metadata
            report.entropy = ctx.metadata.get('entropy', {}).get('generic_whole', ctx.metadata.get('entropy', {}).get('global_file', 0.0))
            
        except Exception as e:
            report.errors.append(f"Pipeline crash: {str(e)}")
            self.logger.error(f"Pipeline failed: {e}")
            
        report.execution_time_ms = (time.time() - start_time) * 1000
        return report

class ATAEEngine:
    def __init__(self):
        self.pipeline = AnalysisPipeline()
        
    def analyze_attachment(self, analysis_id: str, file_bytes: bytes, filename: str, declared_mime: str) -> AnalysisReport:
        return self.pipeline.execute(analysis_id, file_bytes, filename, declared_mime)
