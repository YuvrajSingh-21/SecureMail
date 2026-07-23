import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
django.setup()

from SecureMail.models import ConnectedAccount
count = 0
for acc in ConnectedAccount.objects.all():
    # Calling save() forces django-encrypted-model-fields to encrypt the data
    # IF it decrypts it properly. Let's see if it decrypted the plaintext.
    print(f"Token length: {len(acc.access_token)}")
    acc.save(update_fields=['access_token', 'refresh_token'])
    count += 1
print(f"Migrated {count} records.")
