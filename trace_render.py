import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.models import EmailMessage, ThreatAnalysis
from SecureMail.services.business_logic import EmailService

email = EmailMessage.objects.first()
print("=========================================")
print("1. SQL ROW")
row = EmailMessage.objects.filter(id=email.id).values('analysis__detailed_report').first()
has_gem = 'gemini_explanation' in row['analysis__detailed_report'].get('analysis', {})
print(f"Exists in SQL detailed_report['analysis']: {has_gem}")

print("\n=========================================")
print("2. ORM OBJECT")
email.refresh_from_db()
has_gem_orm = 'gemini_explanation' in email.analysis.detailed_report.get('analysis', {})
print(f"Exists in ORM detailed_report['analysis']: {has_gem_orm}")

print("\n=========================================")
print("3. SERIALIZER / NORMALIZE_PAYLOAD")
email_service = EmailService()
analysis_norm = email_service.get_email_verdict(email)
print("Keys in analysis_norm:", list(analysis_norm.keys()))
print("Exists in analysis_norm:", 'gemini_explanation' in analysis_norm)

print("\n=========================================")
print("4. CONTEXT DICT")
forensic = {'analysis': analysis_norm, 'features': {}}
print("Exists in forensic['analysis']:", 'gemini_explanation' in forensic['analysis'])
if 'gemini_explanation' in forensic['analysis']:
    print("Keys in gemini_explanation:", list(forensic['analysis']['gemini_explanation'].keys()))

print("\n=========================================")
print("5. TEMPLATE RENDER TRACE")
from django.template.loader import render_to_string
from django.test import RequestFactory
import re

request = RequestFactory().get(f'/email/{email.id}/')
request.user = email.user
try:
    html = render_to_string('email-view.html', {'email': email, 'forensic': forensic}, request=request)
    print("Rendered HTML generated successfully.")
    
    # Check if fallback text exists in HTML
    if "Gemini explanation unavailable" in html:
        print("RESULT: Fallback text IS PRESENT in the final HTML.")
    else:
        print("RESULT: Fallback text is NOT present. Real explanation must be rendered.")
        
    # Check for actual gemini content
    gem_data = forensic['analysis'].get('gemini_explanation', {})
    if gem_data and gem_data.get('user_explanation') in html:
        print("RESULT: user_explanation IS PRESENT in the final HTML.")
except Exception as e:
    print("Error rendering template:", str(e))

print("=========================================")
