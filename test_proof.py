import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.models import EmailMessage, ThreatAnalysis
from SecureMail.services.email_pipeline import EmailPipeline
from SecureMail.services.business_logic import EmailService
from django.template import Template, Context
from django.db import connection

print("=========================================")
print("STARTING FULL RUNTIME AUDIT PIPELINE")
print("=========================================")

email = EmailMessage.objects.first()
print(f"Target Email ID: {email.id}")
print("Forcing Pipeline Run to trigger Gemini API...")

pipeline = EmailPipeline()
pipeline.run(email.id, force=True)

email.refresh_from_db()

print("\n=========================================")
print("FINAL DATABASE OBJECT SAVED")
analysis = email.analysis
if analysis:
    print(json.dumps(analysis.detailed_report['analysis']['gemini_explanation'], indent=2))
else:
    print("No analysis found.")
print("=========================================\n")

print("\n=========================================")
print("SQL ROW AFTER SAVE (THREAT ANALYSIS TABLE)")
row = EmailMessage.objects.filter(id=email.id).values('analysis__detailed_report').first()
print(f"Row ID: {email.analysis.id}")
if row and row['analysis__detailed_report']:
    print("Detailed Report JSON length:", len(json.dumps(row['analysis__detailed_report'])))
print("=========================================\n")

print("\n=========================================")
print("TEMPLATE VARIABLE RENDERED")
email_service = EmailService()
analysis_norm = email_service.get_email_verdict(email)
forensic = {'analysis': analysis_norm, 'features': {}}

template_str = """
{% if forensic.analysis.gemini_explanation %}
SUCCESS: RENDERED REAL EXPLANATION
User Explanation: {{ forensic.analysis.gemini_explanation.user_explanation }}
Confidence Comment: {{ forensic.analysis.gemini_explanation.confidence_comment }}
{% else %}
FAILURE: GEMINI RENDERED FALLBACK
{% endif %}
"""

t = Template(template_str)
c = Context({'forensic': forensic})
rendered = t.render(c).strip()
print(rendered)
print("=========================================\n")
