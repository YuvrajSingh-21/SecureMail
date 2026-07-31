import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.models import EmailMessage

def cleanup():
    emails = EmailMessage.objects.filter(sender_email__startswith='validation_')
    count = emails.count()
    print(f"Found {count} validation emails.")
    for email in emails:
        for att in email.attachments.all():
            if att.file:
                try:
                    att.file.delete(save=False)
                except:
                    pass
    emails.delete()
    print("Cleanup complete.")

if __name__ == '__main__':
    cleanup()
