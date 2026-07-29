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

print("=========================================")
print("1. SQL ROW")
row = EmailMessage.objects.filter(id=email.id).values('analysis__detailed_report').first()
sql_payload = row['analysis__detailed_report'].get('analysis', {})
print(f"Contains 'gemini_explanation'?: {'gemini_explanation' in sql_payload}")
if 'gemini_explanation' in sql_payload:
    print(f"SQL Type: {type(sql_payload['gemini_explanation'])}")

print("\n=========================================")
print("2. ORM OBJECT")
email.refresh_from_db()
orm_payload = email.analysis.detailed_report.get('analysis', {})
print(f"Contains 'gemini_explanation'?: {'gemini_explanation' in orm_payload}")

print("\n=========================================")
print("3. SERIALIZER / NORMALIZE_PAYLOAD")
email_service = EmailService()
analysis_norm = email_service.get_email_verdict(email)
print(f"Contains 'gemini_explanation'?: {'gemini_explanation' in analysis_norm}")
if 'gemini_explanation' in analysis_norm:
    print(f"NORM Type: {type(analysis_norm['gemini_explanation'])}")

print("\n=========================================")
print("4. CONTEXT DICTIONARY")
features = email.analysis.detailed_report.get('features', {})
forensic = {'analysis': analysis_norm, 'features': features}
print(f"Contains 'gemini_explanation'?: {'gemini_explanation' in forensic['analysis']}")

print("\n=========================================")
print("5. TEMPLATE VARIABLE VALUES")
# To simulate how Django renders template variables, let's render a custom small template
from django.template import Template, Context
t = Template("User Exp: {{ forensic.analysis.gemini_explanation.user_explanation|default:'NOT_FOUND' }}")
c = Context({'forensic': forensic})
print("Django Template Engine output for variable:")
print(t.render(c))

print("\n=========================================")
print("6. FINAL HTML GENERATED")
factory = RequestFactory()
request = factory.get(f'/email/{email.id}/')
request.user = email.user
response = email_view(request, email.id)
html = response.content.decode('utf-8')
if "Gemini explanation unavailable" in html:
    print("BREAK POINT REACHED: Fallback text is in final HTML!")
    # Find surrounding lines
    lines = html.split('\n')
    for i, line in enumerate(lines):
        if "Gemini explanation unavailable" in line:
            print("Context surrounding fallback:")
            print("\n".join(lines[i-2:i+3]))
            break
else:
    print("SUCCESS: Real explanation found in HTML.")
print("=========================================")
