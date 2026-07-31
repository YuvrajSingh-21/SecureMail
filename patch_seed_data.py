import re
def patch_seed_data():
    path = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/management/commands/seed_data.py'
    with open(path, 'r') as f:
        content = f.read()

    if 'from SecureMail.models import AuditLog' not in content:
        content = content.replace('from SecureMail.models import EmailMessage, ThreatIndicator, ThreatAnalysis', 'from SecureMail.models import EmailMessage, ThreatIndicator, ThreatAnalysis, AuditLog')

    if 'AuditLog.objects.filter(user=user).delete()' not in content:
        content = content.replace('EmailMessage.objects.filter(user=user).delete()', 'EmailMessage.objects.filter(user=user).delete()\n        AuditLog.objects.filter(user=user).delete()')

    mock_audit_code = """
        # Create some mock audit logs
        AuditLog.objects.create(user=user, action='login', category='auth', ip_address='192.168.1.5', user_agent='Chrome on Windows')
        AuditLog.objects.create(user=user, action='mailbox_sync', category='system', metadata={'full_sync': True})
        AuditLog.objects.create(user=user, action='settings_changed', category='system', metadata={'action': 'update_settings'})
        AuditLog.objects.create(user=user, action='report_true_positive', category='security', metadata={'email_id': 1})
        """
    if '# Create some mock audit logs' not in content:
        content = content.replace('self.stdout.write(self.style.SUCCESS(f\'Successfully seeded {len(mock_data)} emails for user {user.username}\'))', mock_audit_code + '\n        self.stdout.write(self.style.SUCCESS(f\'Successfully seeded {len(mock_data)} emails for user {user.username}\'))')

    with open(path, 'w') as f:
        f.write(content)

patch_seed_data()
