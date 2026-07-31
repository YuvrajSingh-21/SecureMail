import os
import re

def patch_sync_views():
    path = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/api/sync_views.py'
    with open(path, 'r') as f:
        content = f.read()

    # Add import if missing
    if 'from ..services.audit_service import AuditService' not in content:
        content = content.replace('from ..models import SyncJob', 'from ..models import SyncJob\nfrom ..services.audit_service import AuditService')

    if "AuditService.log(request.user, 'mailbox_sync'" not in content:
        content = re.sub(
            r"(job = manager.start_sync\(full_sync=full_sync\))",
            r"\1\n        AuditService.log(request.user, 'mailbox_sync', category='system', metadata={'full_sync': full_sync}, request=request)",
            content
        )
    with open(path, 'w') as f:
        f.write(content)

def patch_google_auth():
    path = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/google_auth_views.py'
    with open(path, 'r') as f:
        content = f.read()

    if 'from .services.audit_service import AuditService' not in content:
        content = content.replace('from .decorators import rate_limit_view', 'from .decorators import rate_limit_view\nfrom .services.audit_service import AuditService')

    # Add log on google_callback
    if "AuditService.log(request.user, 'login'" not in content:
        content = re.sub(
            r"(login\(request, user\))",
            r"\1\n            AuditService.log(user, 'login', category='auth', request=request)",
            content
        )

    # connect account
    if "AuditService.log(request.user, 'connect_gmail'" not in content:
        content = re.sub(
            r"(messages.success\(request, \"Gmail account connected successfully!\"\))",
            r"\1\n            AuditService.log(request.user, 'connect_gmail', category='system', request=request)",
            content
        )

    # disconnect account
    if "AuditService.log(request.user, 'disconnect_gmail'" not in content:
        content = re.sub(
            r"(messages.info\(request, \"Gmail account disconnected.\"\))",
            r"\1\n        AuditService.log(request.user, 'disconnect_gmail', category='system', request=request)",
            content
        )
    with open(path, 'w') as f:
        f.write(content)

patch_sync_views()
patch_google_auth()
