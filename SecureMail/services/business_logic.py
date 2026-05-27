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
        if email.gmail_message_id:
            try:
                account = ConnectedAccount.objects.get(user=user)
                GmailService(account).delete_message(email.gmail_message_id)
            except Exception as e:
                logger.warning(f"Failed to trash Gmail message: {str(e)}")
        
        email.in_trash = True
        email.save()
        return True

    def process_new_email(self, email):
        """
        Delegates to the formalized EmailPipeline.
        """
        return self.pipeline.run(email.id)

class ProfileService:
    def __init__(self):
        self.repository = ProfileRepository()

    def update_protection(self, user, is_protected):
        profile = self.repository.get_by_user(user)
        profile.is_protected = is_protected
        profile.save()
        return profile
