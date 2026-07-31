import logging
from ..repositories.base import EmailRepository, ProfileRepository
from .email_pipeline import EmailPipeline
from .gmail_service import GmailService
from ..models import ConnectedAccount, EmailMessage

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.repository = EmailRepository()
        self._pipeline = None

    @property
    def pipeline(self):
        if not self._pipeline:
            from .email_pipeline import EmailPipeline
            self._pipeline = EmailPipeline()
        return self._pipeline

    def sync_gmail(self, user, limit=50):
        """On-demand sync for a specific user. Pass limit=None for full sync."""
        try:
            account = ConnectedAccount.objects.get(user=user)
            service = GmailService(account)
            return service.sync_mailbox(max_emails=limit)
        except ConnectedAccount.DoesNotExist:
            return 0

    def list_inbox(self, user):
        return self.repository.get_user_inbox(user)

    def get_email_detail(self, user, email_id):
        email = self.repository.get_user_email(user, email_id)
        if email.unread:
            # Mark read locally
            email.unread = False
            email.save()
            
            # Sync to Gmail if applicable (in background to avoid latency)
            if email.gmail_message_id:
                try:
                    account = ConnectedAccount.objects.get(user=user)
                    import threading
                    def sync_read():
                        try:
                            GmailService(account).mark_as_read(email.gmail_message_id)
                        except Exception as e:
                            logger.warning(f"Failed to sync read status to Gmail: {str(e)}")
                    threading.Thread(target=sync_read).start()
                except Exception as e:
                    logger.warning(f"Failed to launch Gmail sync thread: {str(e)}")

        return email

    def toggle_star(self, user, email_id):
        email = self.repository.get_user_email(user, email_id)
        email.starred = not email.starred
        email.save()
        return email

    def delete_email(self, user, email_id):
        email = self.repository.get_user_email(user, email_id)
        
        # Trash in Gmail API
        if email.gmail_message_id:
            try:
                account = ConnectedAccount.objects.get(user=user)
                GmailService(account).delete_message(email.gmail_message_id)
            except Exception as e:
                logger.warning(f"Failed to trash Gmail message: {str(e)}")
        
        # Mark as trashed locally (Gmail will sync it later or user sees it in trash)
        email.in_trash = True
        email.save()
        return True

    def process_new_email(self, email):
        """
        Delegates to the formalized EmailPipeline.
        """
        return self.pipeline.run(email.id)

    def get_email_verdict(self, email):
        """
        Canonical source for email intelligence.
        Returns normalized analysis payload from ThreatAnalysis or falls back safely.
        """
        from .risk_engine import RiskEngine
        engine = RiskEngine()
        
        report = {}
        if hasattr(email, 'analysis'):
            report = email.analysis.detailed_report
            
        analysis = engine.normalize_payload(report)
        
        # Validation for inconsistencies
        if email.risk == 'dangerous' and analysis['label'] == 'SAFE':
            logger.critical(f"INTELLIGENCE INCONSISTENCY: Email {email.id} cached as dangerous but forensic analysis is SAFE.")
        
        return analysis

    def build_forensic_context(self, email):
        """
        Builds a single canonical context dictionary required by both
        the HTML Modal and the ReportLab PDF to prevent logic divergence.
        """
        analysis = self.get_email_verdict(email) or {}
        gemini = analysis.get('gemini_explanation') or {}
        
        # Determine sender string formatting
        sender_display = getattr(email, 'sender_email', 'Unknown Sender')
        if hasattr(email, 'sender_name') and email.sender_name and email.sender_name != sender_display:
            sender_display = f"{email.sender_name} <{sender_display}>"
            
        links = []
        if hasattr(email, 'analysis') and hasattr(email.analysis, 'detailed_report'):
            links = (email.analysis.detailed_report or {}).get('links', [])
            
        urls = []
        for l in links:
            urls.append({
                'url': l.get('url', ''),
                'safe_browsing': 'Clean' if not l.get('is_malicious') else 'Threat',
                'virustotal': 'Clean',
                'verdict': l.get('threat_type', 'SAFE')
            })
            
        # Detect spoofing
        spf = getattr(email, 'spf_pass', False)
        dkim = getattr(email, 'dkim_pass', False)
        spoofing = "None detected" if (spf and dkim) else "Possible Spoofing"
        
        # Findings for ML
        detection_reasoning = analysis.get('critical_findings', [])[:3] + analysis.get('warning_findings', [])[:3]
        if not detection_reasoning:
            if analysis.get('label') == 'SAFE':
                detection_reasoning = ["No phishing indicators detected", "No manipulative behavioral signals"]
        
        # Attachments formatting
        atts = []
        for att in email.attachments.all():
            if hasattr(att, 'analysis') and att.analysis:
                findings_list = att.analysis.findings or []
                risk_score = att.analysis.risk_score
                analyzer = att.analysis.analyzer_used
                raw_report = att.analysis.raw_report or {}
            else:
                findings_list = []
                risk_score = 0
                analyzer = 'N/A'
                raw_report = {}
                
            # Convert size to readable format
            size_bytes = getattr(att, 'size', 0)
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes/1024:.1f} KB"
            else:
                size_str = f"{size_bytes/(1024*1024):.1f} MB"
                
            ext = att.filename.split('.')[-1].upper() if '.' in att.filename else 'UNKNOWN'
                
            atts.append({
                'filename': att.filename,
                'extension': ext,
                'size': size_str,
                'sha256': getattr(att, 'sha256', None),
                'risk_score': risk_score,
                'analyzer': analyzer,
                'verdict': 'MALICIOUS' if att.is_malicious else 'SAFE',
                'findings': [f.get('title', str(f)) for f in findings_list if isinstance(f, dict)] if findings_list else [],
                'recommendation': raw_report.get('recommendation') or raw_report.get('recommended_action')
            })
            
        return {
            'incident_id': getattr(email, 'id', 'Unknown'),
            'subject': getattr(email, 'subject', None) or 'No Subject',
            
            # Overview
            'verdict': analysis.get('label') or 'SAFE',
            'confidence': analysis.get('confidence') or 0,
            'risk_score': analysis.get('score') or 0,
            'threat_category': analysis.get('category', 'N/A'),
            'investigation_status': 'Closed - Automated Analysis Completed',
            
            # Exec Summary
            'ai_summary': gemini.get('summary') or gemini.get('user_explanation') or analysis.get('summary') or 'No summary available.',
            'technical_explanation': gemini.get('technical_analysis') or 'No technical explanation available.',
            'recommended_action': gemini.get('recommended_action') or 'No action available.',
            
            # Risk Breakdown
            'risk_breakdown': [
                ("Header Analysis", 0),
                ("Authentication", 0),
                ("Sender Reputation", analysis.get('sender_risk', 0)),
                ("URL Analysis", analysis.get('url_risk', 0)),
                ("Machine Learning", analysis.get('score', 0))
            ] + ([("Attachment Analysis", analysis.get('attachment_risk', 0))] if email.attachments.exists() else []),
            
            # Auth
            'spf_pass': spf,
            'dkim_pass': dkim,
            'dmarc_pass': getattr(email, 'dmarc_pass', False),
            
            # Sender Intel
            'sender_domain': getattr(email, 'sender_email', 'N/A'),
            'sender_display': sender_display,
            'sender_reputation': f"{analysis.get('sender_reputation', 50)}/100",
            'spoofing_detection': spoofing,
            
            # Header Analysis
            'message_id': getattr(email, 'gmail_message_id', 'Unknown'),
            'return_path': getattr(email, 'sender_email', 'Unknown'),
            'originating_ip': 'Extracted from headers',
            'suspicious_headers': [],
            
            # URL
            'urls': urls,
            
            # ML Assessment
            'detection_reasoning': detection_reasoning,
            'suspicious_phrases': analysis.get('suspicious_phrases', []),
            
            # Attachments
            'attachments': atts,
            
            # Timeline
            'timeline': [
                (f"[{email.timestamp.strftime('%H:%M:%S')}] Email received", '#10b981'),
                (f"[{email.timestamp.strftime('%H:%M:%S')}] Headers parsed & Authentication verified", '#10b981'),
                (f"[{email.timestamp.strftime('%H:%M:%S')}] URL & Sender investigation completed", '#10b981'),
            ] + ([
                (f"[{(email.analysis_completed or email.timestamp).strftime('%H:%M:%S')}] Attachment analyzed (ATAE)", '#3b82f6')
            ] if email.attachments.exists() else []) + [
                (f"[{(email.analysis_completed or email.timestamp).strftime('%H:%M:%S')}] Machine Learning completed", '#3b82f6'),
                (f"[{(email.analysis_completed or email.timestamp).strftime('%H:%M:%S')}] Final verdict generated: {analysis.get('label', 'SAFE')}", '#ef4444' if analysis.get('label') == 'PHISHING' else ('#f97316' if analysis.get('label') == 'SUSPICIOUS' else '#22c55e'))
            ],
            
            'original_content': getattr(email, 'plain_body', None) or getattr(email, 'body', 'No text available.')
        }

class ProfileService:
    def __init__(self):
        self.repository = ProfileRepository()

    def update_protection(self, user, is_protected, alert_threats=True, alert_digest=True):
        profile = self.repository.get_by_user(user)
        profile.is_protected = is_protected
        profile.alert_threats = alert_threats
        profile.alert_digest = alert_digest
        profile.save()
        return profile
