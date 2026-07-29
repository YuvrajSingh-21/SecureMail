import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.services.pdf.forensic_report import ForensicPDFReport
from SecureMail.services.pdf.sections import *
from reportlab.platypus import Paragraph

context = {
    'incident_id': '12345',
    'verdict': 'PHISHING',
    'risk_score': 95,
    'executive_summary': 'This is a test.' * 100,
    'analyst_explanation': 'Test.' * 200,
    'technical_analysis': 'Tech.' * 200,
    'confidence_assessment': 'Conf.' * 50,
    'recommended_action': 'Action.' * 10,
    'original_content': 'Raw html' * 2000,
    'threat_indicators': ['Bad URL'] * 50,
    'links': [{'url': 'http://evil.com', 'threat_type': 'MALWARE'}] * 50,
    'red_flags': ['Urgent'] * 20
}

report = ForensicPDFReport(context)
story = []
story.extend(build_header(report.context))
story.extend(build_executive_summary(report.context))
story.extend(build_ai_investigation(report.context))
story.extend(build_red_flags(report.context))
story.extend(build_threat_indicators(report.context))
story.extend(build_iocs_and_auth(report.context))
story.extend(build_timeline(report.context))
story.extend(build_email_metadata(report.context))
story.extend(build_original_content(report.context))

print("STORY FLOWABLES:")
for f in story:
    print(type(f).__name__)

try:
    report.generate('/tmp/test.pdf')
    print("SUCCESS: PDF Generated")
except Exception as e:
    print(f"ERROR: {e}")
