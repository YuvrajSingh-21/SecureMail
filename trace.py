import os
import django
import sys
import base64
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
django.setup()

from SecureMail.models import EmailMessage

email = EmailMessage.objects.filter(html_body__isnull=False).exclude(html_body='').first()
if not email:
    print("No email with html_body found")
    sys.exit()

print(f"ID: {email.id}, Subject: {email.subject}, Gmail ID: {email.gmail_message_id}")
print(f"\n--- DB FIELD (First 300) ---")
print(email.html_body[:300])

