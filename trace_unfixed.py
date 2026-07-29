import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.models import EmailMessage
from SecureMail.services.business_logic import EmailService

# Find an email that does NOT have gemini_explanation
email = None
for e in EmailMessage.objects.all():
    has_gem = False
    if hasattr(e, 'analysis') and e.analysis:
        rep = e.analysis.detailed_report
        if 'gemini_explanation' in rep.get('analysis', {}):
            has_gem = True
    if not has_gem:
        email = e
        break

if not email:
    print("All emails have gemini explanation now.")
    exit()

print(f"Tracing Email {email.id} (never successfully processed by Gemini)")

email_service = EmailService()
# 1. SQL / ORM
print("1. SQL / ORM: gemini_explanation exists in detailed_report['analysis']:", 'gemini_explanation' in email.analysis.detailed_report.get('analysis', {}))

# 3. NORMALIZE
analysis_norm = email_service.get_email_verdict(email)
print("3. normalize_payload: gemini_explanation exists:", 'gemini_explanation' in analysis_norm)

# 4. Context
forensic = {'analysis': analysis_norm, 'features': {}}
print("4. Context Dict: forensic['analysis']['gemini_explanation'] exists:", 'gemini_explanation' in forensic['analysis'] and forensic['analysis']['gemini_explanation'] is not None)

# 5. Template
from django.template.loader import render_to_string
from django.test import RequestFactory
request = RequestFactory().get(f'/email/{email.id}/')
request.user = email.user
html = render_to_string('email-view.html', {'email': email, 'forensic': forensic}, request=request)
print("5. HTML Result: Fallback present?", "Gemini explanation unavailable" in html)
