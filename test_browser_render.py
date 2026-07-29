import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from django.test import Client
from SecureMail.models import EmailMessage

client = Client()
email = EmailMessage.objects.get(id=10578)
client.force_login(email.user)

response = client.get(f'/email/{email.id}/')
print("Status Code:", response.status_code)
html = response.content.decode('utf-8')
if "Gemini explanation unavailable" in html:
    print("FALLBACK STILL RENDERED IN BROWSER VIEW!")
else:
    print("REAL EXPLANATION RENDERED IN BROWSER VIEW!")
    
if "This email is a benign message regarding a video template" in html:
    print("Actual Gemini text found.")
else:
    print("Actual Gemini text NOT found.")
