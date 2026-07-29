import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from django.test import Client, RequestFactory
from SecureMail.models import EmailMessage

client = Client()

# Take an email that doesn't have explanation
email = EmailMessage.objects.last()
from SecureMail.services.email_pipeline import EmailPipeline
EmailPipeline().run(email.id)

# Clear cache
if hasattr(email, 'analysis') and email.analysis and 'analysis' in email.analysis.detailed_report:
    if 'gemini_explanation' in email.analysis.detailed_report['analysis']:
        del email.analysis.detailed_report['analysis']['gemini_explanation']
        email.analysis.save(update_fields=['detailed_report'])

print(f"Testing lazy generation for Email {email.id}")
client.force_login(email.user)
response = client.post(f"/email/{email.id}/generate-explanation/", HTTP_HOST='127.0.0.1')
print("Status:", response.status_code)
try:
    print(response.json())
except Exception as e:
    print("Error parsing JSON:", e)
    print(response.content)

# Test cache hit
print("\nTesting Cache Hit:")
response2 = client.post(f"/email/{email.id}/generate-explanation/", HTTP_HOST='127.0.0.1')
print("Status:", response2.status_code)
try:
    print("Status in JSON:", response2.json().get('status'))
except Exception as e:
    print(e)
