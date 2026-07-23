from django.core.management.base import BaseCommand
from SecureMail.models import EmailMessage

class Command(BaseCommand):
    help = 'Permanently deletes emails that have been marked as is_remote_deleted=True to prevent database bloat.'

    def handle(self, *args, **options):
        stale_emails = EmailMessage.objects.filter(is_remote_deleted=True)
        count = stale_emails.count()
        
        if count == 0:
            self.stdout.write(self.style.SUCCESS("No stale emails to clean up."))
            return
            
        self.stdout.write(f"Found {count} remotely deleted emails. Deleting...")
        stale_emails.delete()
        self.stdout.write(self.style.SUCCESS(f"Successfully deleted {count} stale emails."))
