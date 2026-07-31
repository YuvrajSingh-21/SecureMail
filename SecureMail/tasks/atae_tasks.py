import threading
import logging
from django.db import transaction

logger = logging.getLogger(__name__)

def _run_atae_background(attachment_id):
    from ..models import Attachment, AttachmentAnalysis
    from ..services.atae.integration.orchestrator import ATAEEngine
    from ..services.atae.integration.bootstrap import register_all_analyzers
    from ..services.email_pipeline import EmailPipeline

    try:
        att = Attachment.objects.get(id=attachment_id)
        att.scan_status = 'ANALYZING'
        att.save(update_fields=['scan_status'])

        # Register analyzers (in case thread context needs it)
        register_all_analyzers()
        
        with open(att.file.path, 'rb') as f:
            file_bytes = f.read()

        engine = ATAEEngine()
        report = engine.analyze_attachment(f"att-{att.id}", file_bytes, att.filename, att.content_type)

        with transaction.atomic():
            is_malicious = report.risk_level in ["MALICIOUS", "SUSPICIOUS"]

            # Serialize findings
            findings_serialized = []
            for f in report.findings:
                if hasattr(f, '__dict__'):
                    f_dict = f.__dict__.copy()
                    # Convert enums to string if needed
                    if hasattr(f_dict.get('severity'), 'name'):
                        f_dict['severity'] = f_dict['severity'].name
                    if hasattr(f_dict.get('confidence'), 'name'):
                        f_dict['confidence'] = f_dict['confidence'].name
                    findings_serialized.append(f_dict)
                else:
                    findings_serialized.append(f)

            AttachmentAnalysis.objects.create(
                attachment=att,
                risk_score=report.risk_score,
                risk_level=report.risk_level,
                findings=findings_serialized,
                metadata=report.metadata,
                iocs=report.iocs,
                entropy=report.entropy,
                analyzer_used=report.analyzer_used,
                analysis_version=report.pipeline_version,
                execution_time_ms=report.execution_time_ms,
                errors=report.errors,
                raw_report={}
            )

            att.scan_status = 'COMPLETED'
            att.is_malicious = is_malicious
            att.save(update_fields=['scan_status', 'is_malicious'])

        # Recalculate Email Risk
        pipeline = EmailPipeline()
        pipeline.run(att.email.id)

    except Exception as e:
        logger.error(f"ATAE background task failed: {e}")
        try:
            att = Attachment.objects.get(id=attachment_id)
            att.scan_status = 'FAILED'
            att.save(update_fields=['scan_status'])
        except:
            pass

class ATAETask:
    @staticmethod
    def delay(attachment_id):
        t = threading.Thread(target=_run_atae_background, args=(attachment_id,))
        t.daemon = True
        t.start()

analyze_attachment_task = ATAETask()
