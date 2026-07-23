import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
django.setup()

from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("SELECT access_token FROM \"SecureMail_connectedaccount\" LIMIT 1")
    row = cursor.fetchone()
    print("Raw DB access_token starts with:", str(row[0])[:50] if row else "None")
