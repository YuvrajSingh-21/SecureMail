import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()
from SecureMail.models import EmailMessage

e = EmailMessage.objects.filter(sender_email__icontains='linkedin').exclude(html_body='').first()
if e:
    print("ID:", e.id)
    print("Subject:", e.subject)
    print("HTML Length:", len(e.html_body or ''))
    
    # Just print the first 500 chars to see what was stored
    print("HTML Start:", e.html_body[:500] if e.html_body else "None")
else:
    print("No LinkedIn email found with HTML.")
