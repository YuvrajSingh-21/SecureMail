from django.core.management.base import BaseCommand
from SecureMail.models import EmailMessage
from SecureMail.services.email_pipeline import EmailPipeline
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Runs security analysis on all emails that have not yet been analyzed or force re-analysis.'

    def add_arguments(self, parser):
        parser.add_argument('--force', action='store_true', help='Force re-analysis of already completed emails')

    def handle(self, *args, **options):
        force = options['force']
        
        if force:
            emails = EmailMessage.objects.all()
        else:
            # Fetch emails with missing analysis or missing new body fields
            emails = EmailMessage.objects.filter(Q(analysis_completed__isnull=True) | Q(plain_body__isnull=True))
            
        total = emails.count()
        
        if total == 0:
            self.stdout.write(self.style.SUCCESS("All emails are already up to date."))
            return

        self.stdout.write(f"Starting analysis for {total} emails (Force={force})...")
        
        pipeline = EmailPipeline()
        analyzed_count = 0
        refreshed_count = 0
        failed_count = 0
        
        for email in emails:
            try:
                # Refresh body if missing new fields or forcing
                if (not email.plain_body or force) and email.gmail_message_id:
                    from SecureMail.services.gmail_service import GmailService
                    from SecureMail.models import ConnectedAccount
                    try:
                        account = ConnectedAccount.objects.get(user=email.user)
                        service = GmailService(account)
                        full_msg = service.get_message(email.gmail_message_id)
                        if full_msg:
                            parsed = service.parse_message_data(full_msg)
                            email.plain_body = parsed['plain_body']
                            email.html_body = parsed['html_body']
                            # Reset analysis to allow pipeline to run fresh
                            email.analysis_completed = None
                            email.save()
                            refreshed_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to refresh body for {email.id}: {str(e)}")

                success = pipeline.run(email.id)
                if success:
                    analyzed_count += 1
                else:
                    failed_count += 1
                
                if (analyzed_count + failed_count) % 10 == 0:
                    self.stdout.write(f"Processed {analyzed_count + failed_count}/{total}...")
            except Exception as e:
                failed_count += 1
                logger.error(f"Failed to process email {email.id}: {str(e)}")

        self.stdout.write(self.style.SUCCESS(f"Task complete. Analyzed: {analyzed_count}, Refreshed: {refreshed_count}, Failed: {failed_count}"))
