import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.models import EmailMessage, ThreatAnalysis
from SecureMail.services.email_pipeline import EmailPipeline
from django.template import Template, Context
import json

print("\n--- STARTING EXECUTION AUDIT ---")
email = EmailMessage.objects.first()
if not email:
    print("No email found.")
    exit()

print(f"Testing with Email ID: {email.id}")

# Force run pipeline
pipeline = EmailPipeline()
pipeline.run(email.id, force=True)

# Fetch from DB
email.refresh_from_db()
print("\n=========================================")
print("DATABASE STATE AFTER SAVE")
analysis = email.analysis
if not analysis:
    print("NO ANALYSIS OBJECT FOUND IN DB!")
else:
    print("Analysis Object exists.")
    print("Detailed Report (JSON):")
    # Pretty print the detailed_report
    print(json.dumps(analysis.detailed_report, indent=2))
print("=========================================\n")

print("\n=========================================")
print("TEMPLATE RENDERING")
template_str = """
{% if forensic.analysis.gemini_explanation %}
GEMINI RENDERED:
{{ forensic.analysis.gemini_explanation.user_explanation }}
{% else %}
GEMINI FALLBACK RENDERED:
Gemini explanation unavailable.
{% endif %}
"""
t = Template(template_str)
c = Context({'forensic': {'analysis': analysis.detailed_report if analysis else {}}})
rendered = t.render(c)
print(rendered.strip())
print("=========================================\n")
