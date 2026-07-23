import os
import django
import base64
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
django.setup()

from SecureMail.models import EmailMessage, Profile
from SecureMail.services.gmail_service import GmailService

# Get the first user profile to access Gmail
profile = Profile.objects.filter(connected_gmail__isnull=False).first()
if not profile:
    print("No connected gmail")
    sys.exit()

gmail = GmailService(profile)
# Find an email that has html_body in our DB
db_email = EmailMessage.objects.filter(html_body__isnull=False).first()
gmail_id = db_email.gmail_message_id

print(f"Tracing email {gmail_id}")

raw = gmail.get_message(gmail_id)
payload = raw.get('payload', {})
parts = payload.get('parts', [])

html_part = None
for p in parts:
    if p.get('mimeType') == 'text/html':
        html_part = p
        break
    if 'parts' in p:
        for sub in p['parts']:
            if sub.get('mimeType') == 'text/html':
                html_part = sub
                break

if not html_part:
    print("No HTML part found in raw MIME.")
    sys.exit()

raw_b64 = html_part['body']['data']
raw_b64 += '=' * ((4 - len(raw_b64) % 4) % 4)
raw_html = base64.urlsafe_b64decode(raw_b64).decode('utf-8', errors='ignore')

print("\n--- STEP 1: Gmail MIME ---")
print("First 100:", raw_html[:100].replace('\n', ' '))
print("Email Title exists:", "Meet WEB1" in raw_html)
print("<title> exists:", "<title" in raw_html.lower())
print("<body> exists:", "<body" in raw_html.lower())

# Now trace parse_message_data
parsed = gmail.parse_message_data(raw)
parsed_html = parsed.get('html_body', '')

print("\n--- STEP 2: parse_message_data() ---")
print("First 100:", parsed_html[:100].replace('\n', ' '))
print("Email Title exists:", "Meet WEB1" in parsed_html)
print("<title> exists:", "<title" in parsed_html.lower())
print("<body> exists:", "<body" in parsed_html.lower())
print("Changed:", raw_html != parsed_html)

# DB save 
db_html = db_email.html_body
print("\n--- STEP 3: Database Field ---")
print("First 100:", db_html[:100].replace('\n', ' '))
print("Email Title exists:", "Meet WEB1" in db_html)
print("<title> exists:", "<title" in db_html.lower())
print("<body> exists:", "<body" in db_html.lower())
print("Changed from parsed:", parsed_html != db_html)

