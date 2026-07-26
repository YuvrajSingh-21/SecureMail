import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
django.setup()

import base64

# Create a mock LinkedIn payload since Gmail API is rate-limited
html_content = '<html><body><script type="application/ld+json">\n{"@context":"http://schema.org","@type":"EmailMessage"}\n</script></body></html>'
plain_content = "Achal is waiting for your response"

b_html = base64.urlsafe_b64encode(html_content.encode()).decode()
b_plain = base64.urlsafe_b64encode(plain_content.encode()).decode()

msg_payload = {
    'payload': {
        'parts': [
            {'mimeType': 'text/plain', 'body': {'data': b_plain}},
            {'mimeType': 'text/html', 'body': {'data': b_html}}
        ]
    }
}

parts = msg_payload['payload'].get('parts', [])
html_parts = []
plain_parts = []

def collect_parts(p_list):
    for p in p_list:
        m_type = p.get('mimeType', '')
        if p.get('filename') or m_type.startswith('application/'): continue
        if m_type == 'text/html': html_parts.append(p)
        elif m_type == 'text/plain': plain_parts.append(p)
        elif 'parts' in p: collect_parts(p['parts'])

collect_parts(parts)

print(f"1. html_parts count: {len(html_parts)}")
print(f"2. plain_parts count: {len(plain_parts)}")

for p in html_parts:
    print(f"- content-type: text/html")
    b_data = p.get('body', {}).get('data', '')
    b_data += '=' * ((4 - len(b_data) % 4) % 4)
    decoded = base64.urlsafe_b64decode(b_data).decode('utf-8', errors='ignore')
    print(f"- decoded length: {len(decoded)}")
    print(f"- first 200 characters: {repr(decoded[:200])}")

print("-" * 40)
print(f"Immediately before: if not self._is_structured_data(decoded)")
print(f"decoded length: {len(decoded)}")

def buggy_is_structured_data(text):
    trimmed = text.strip()
    if trimmed.startswith('{') and '"@context"' in trimmed: return True
    if 'schema.org' in trimmed and ('"@type"' in trimmed or '"@graph"' in trimmed): return True
    return False

return_val = buggy_is_structured_data(decoded)
print(f"Immediately after: print returned value.")
print(f"return value: {return_val}")

bodies = {'html': '', 'plain': ''}
if not return_val:
    bodies['html'] = decoded

print(f"Immediately before returning from _get_body_from_parts():")
print(f"len(bodies['html']): {len(bodies['html'])}")
print(f"len(bodies['plain']): {len(bodies['plain'])}")

# The sync manager step
parsed = {'html_body': bodies['html'], 'plain_body': bodies['plain']}
print(f"Immediately before saving in sync_manager:")
print(f"len(parsed['html']): {len(parsed['html_body'])}")
print(f"len(parsed['plain']): {len(parsed['plain_body'])}")

from SecureMail.models import EmailMessage
email = EmailMessage.objects.filter(body__icontains='Achal').first()
print(f"After saving, query the database for THAT SAME email")
print(f"len(html_body): {len(email.html_body) if email and email.html_body else 0}")
print(f"first 300 chars of html_body: {repr(email.html_body[:300]) if email and email.html_body else 'None'}")
