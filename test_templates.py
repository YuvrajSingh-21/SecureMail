import os
import django
from django.template.loader import render_to_string
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

templates_to_test = [
    'index.html', 'about.html', 'contact.html', 'inbox.html',
    'dashboard.html', 'analytics.html', 'reports.html', 'settings.html'
]

errors = 0
for t in templates_to_test:
    try:
        render_to_string(t)
        print(f"SUCCESS: {t}")
    except Exception as e:
        print(f"ERROR in {t}: {e}")
        errors += 1

if errors > 0:
    exit(1)
