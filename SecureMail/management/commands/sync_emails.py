from django.core.management.base import BaseCommand
from SecureMail.models import ConnectedAccount, EmailMessage
from SecureMail.services.gmail_service import GmailService
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Synchronizes emails from Gmail for all connected accounts'

    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, default=100, help='Max emails to fetch per user (default 100)')
        parser.add_argument('--all', action='store_true', help='Fetch entire mailbox (overrides --limit)')

    def handle(self, *args, **options):
        accounts = ConnectedAccount.objects.all()
        limit = None if options['all'] else options['limit']
        
        if not accounts.exists():
            self.stdout.write(self.style.WARNING("No connected Gmail accounts found."))
            return

        for account in accounts:
            if options['all']:
                self.stdout.write(f"Starting FULL sync for {account.email}...")
            else:
                self.stdout.write(f"Syncing latest {limit} emails for {account.email}...")
                
            try:
                service = GmailService(account)
                
                # Get counts before
                before_count = EmailMessage.objects.filter(user=account.user).count()
                
                service.sync_mailbox(max_emails=limit)
                
                # Get counts after
                after_count = EmailMessage.objects.filter(user=account.user).count()
                new_imported = after_count - before_count
                
                self.stdout.write(self.style.SUCCESS(f"Sync complete for {account.email}. Total in DB: {after_count} (+{new_imported} new)"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Failed to sync {account.email}: {str(e)}"))
                logger.error(f"Sync failed for {account.email}", exc_info=True)
                continue
