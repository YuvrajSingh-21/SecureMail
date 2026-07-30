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
            
        return {
            'incident_id': getattr(email, 'id', 'Unknown'),
            'subject': getattr(email, 'subject', None) or 'No Subject',
            'sender_email': getattr(email, 'sender_email', 'Unknown Sender'),
            'sender_display': sender_display,
            'date': email.timestamp.strftime('%B %d, %Y %I:%M %p') if getattr(email, 'timestamp', None) else 'Unknown Date',
            
            'verdict': analysis.get('label') or 'SAFE',
            'confidence': analysis.get('confidence') or 0,
            'risk_score': analysis.get('score') or 0,
            
            'executive_summary': gemini.get('summary') or analysis.get('summary') or 'No data available.',
            
            'analyst_explanation': gemini.get('user_explanation') or 'No data available.',
            'technical_analysis': gemini.get('technical_analysis') or 'No data available.',
            'confidence_assessment': gemini.get('confidence_comment') or 'No data available.',
            'recommended_action': gemini.get('recommended_action') or 'No data available.',
            
            'red_flags': gemini.get('red_flags') or [],
            
            'trusted_sender': analysis.get('trusted_sender') or False,
            'sender_reputation': analysis.get('sender_reputation') or 0,
            
            'threat_indicators': analysis.get('risk_factors') or [],
            
            'complexity_score': analysis.get('complexity_score', 'N/A'),
            'entropy_score': analysis.get('entropy_score', 'N/A'),
            
            'trigger_phrases': analysis.get('suspicious_phrases', []),
            
            'links': links,
            
            'spf_pass': getattr(email, 'spf_pass', False),
            'dkim_pass': getattr(email, 'dkim_pass', False),
            'dmarc_pass': getattr(email, 'dmarc_pass', False),
            
            'original_content': getattr(email, 'plain_text', None) or getattr(email, 'body', 'No text available.')
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
