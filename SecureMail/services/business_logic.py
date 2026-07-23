import logging
from ..repositories.base import EmailRepository, ProfileRepository
from .email_pipeline import EmailPipeline
from .gmail_service import GmailService
from ..models import ConnectedAccount, EmailMessage

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.repository = EmailRepository()
        self.pipeline = EmailPipeline()

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
            
            # Sync to Gmail if applicable
            if email.gmail_message_id:
                try:
                    account = ConnectedAccount.objects.get(user=user)
                    GmailService(account).mark_as_read(email.gmail_message_id)
                except Exception as e:
                    logger.warning(f"Failed to sync read status to Gmail: {str(e)}")

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
