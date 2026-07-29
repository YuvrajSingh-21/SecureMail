import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from django.test import RequestFactory
from SecureMail.models import EmailMessage
from SecureMail.services.business_logic import EmailService
from SecureMail.views import email_view

email = EmailMessage.objects.get(id=10578)

print("\n--- STEP 1: SQL ROW ---")
row = EmailMessage.objects.filter(id=email.id).values('analysis__detailed_report').first()
db_has_gem = 'gemini_explanation' in row['analysis__detailed_report'].get('analysis', {})
print(f"gemini_explanation in SQL row payload? {db_has_gem}")

print("\n--- STEP 2: ORM OBJECT ---")
email.refresh_from_db()
orm_has_gem = 'gemini_explanation' in email.analysis.detailed_report.get('analysis', {})
print(f"gemini_explanation in ORM object? {orm_has_gem}")

print("\n--- STEP 3: NORMALIZE_PAYLOAD / SERIALIZER ---")
email_service = EmailService()
analysis_norm = email_service.get_email_verdict(email)
print(f"gemini_explanation in analysis_norm? {'gemini_explanation' in analysis_norm}")
if 'gemini_explanation' in analysis_norm:
    print(f"Value of gemini_explanation in analysis_norm is dict: {isinstance(analysis_norm['gemini_explanation'], dict)}")

print("\n--- STEP 4: CONTEXT DICTIONARY ---")
features = email.analysis.detailed_report.get('features', {})
forensic = {'analysis': analysis_norm, 'features': features}
print(f"gemini_explanation in forensic context? {'gemini_explanation' in forensic['analysis']}")

print("\n--- STEP 5: TEMPLATE VARIABLE VALUES ---")
print("We pass 'forensic' directly to the template.")

print("\n--- STEP 6: FINAL HTML ---")
factory = RequestFactory()
request = factory.get(f'/email/{email.id}/')
request.user = email.user
response = email_view(request, email.id)
html = response.content.decode('utf-8')
print(f"Fallback present? {'Gemini explanation unavailable' in html}")
if "Gemini explanation unavailable" not in html:
    print("User explanation is successfully rendered in HTML!")
