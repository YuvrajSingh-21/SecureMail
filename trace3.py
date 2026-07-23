import os
import django
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
django.setup()

from SecureMail.models import EmailMessage

db_email = EmailMessage.objects.filter(html_body__isnull=False).exclude(html_body='').first()
if not db_email:
    print("No HTML emails")
    sys.exit()

print(f"ID: {db_email.id}, Subject: {db_email.subject}")
print("--- DB HTML ---")
print(db_email.html_body[:500])

