import re
import os

def process_file():
    views_path = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/views.py'
    with open(views_path, 'r') as f:
        content = f.read()

    # Add imports
    if 'from .services.audit_service import AuditService' not in content:
        content = content.replace(
            'from .services.sync_manager import SyncManager',
            'from .services.sync_manager import SyncManager\nfrom .services.audit_service import AuditService\nfrom .services.profile_service import ProfileService as MetricProfileService'
        )

    # 1. logout_view
    content = re.sub(
        r'(def logout_view\(request\):\n)(\s+logout\(request\))',
        r"\1    if request.user.is_authenticated:\n        AuditService.log(request.user, 'logout', category='auth', request=request)\n\2",
        content
    )

    # 2. sync_gmail
    content = re.sub(
        r'(job = manager.start_sync\(full_sync=full_sync\))',
        r"\1\n    AuditService.log(request.user, 'mailbox_sync', category='system', metadata={'full_sync': full_sync}, request=request)",
        content
    )

    # 3. inbox bulk actions
    # empty_trash
    content = re.sub(
        r'(msg_text = f\'Permanently deleted \{count\} emails from Trash\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n            AuditService.log(request.user, 'empty_trash', category='email', metadata={'count': count}, request=request)\n            MetricProfileService.recalculate_security_metrics(request.user)",
        content
    )

    # delete (in trash -> delete forever)
    content = re.sub(
        r'(msg_text = f\'Permanently deleted \{count\} emails\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n                    AuditService.log(request.user, 'permanent_delete', category='email', metadata={'count': count}, request=request)\n                    MetricProfileService.recalculate_security_metrics(request.user)",
        content
    )
    
    # move to trash
    content = re.sub(
        r'(msg_text = f\'Moved \{len\(email_ids\)\} emails to trash\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n                    AuditService.log(request.user, 'delete_email', category='email', metadata={'count': len(email_ids)}, request=request)\n                    MetricProfileService.recalculate_security_metrics(request.user)",
        content
    )

    # delete_forever (bulk) - wait, this might match the same as delete forever above. Let's make it robust.
    content = re.sub(
        r'(elif action == \'delete_forever\':[\s\S]*?msg_text = f\'Permanently deleted \{count\} emails\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n                AuditService.log(request.user, 'permanent_delete', category='email', metadata={'count': count}, request=request)\n                MetricProfileService.recalculate_security_metrics(request.user)",
        content
    )

    # restore
    content = re.sub(
        r'(msg_text = f\'Restored \{len\(email_ids\)\} emails to Inbox\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n                AuditService.log(request.user, 'restore_email', category='email', metadata={'count': len(email_ids)}, request=request)\n                MetricProfileService.recalculate_security_metrics(request.user)",
        content
    )

    # archive
    content = re.sub(
        r'(msg_text = f\'Archived \{len\(email_ids\)\} emails\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n                AuditService.log(request.user, 'archive_email', category='email', metadata={'count': len(email_ids)}, request=request)",
        content
    )

    # unarchive
    content = re.sub(
        r'(msg_text = f\'Moved \{len\(email_ids\)\} emails to Inbox\.\'\n\s+messages\.success\(request, msg_text\))',
        r"\1\n                AuditService.log(request.user, 'unarchive_email', category='email', metadata={'count': len(email_ids)}, request=request)",
        content
    )

    # 4. toggle_star isn't requested but delete_email is.
    content = re.sub(
        r'(def delete_email\(request, id\):[\s\S]*?email\.save\(\)\n\s+messages\.success\(request, "Email deleted successfully\."\))',
        r"\1\n    AuditService.log(request.user, 'delete_email', category='email', metadata={'email_id': id}, request=request)\n    MetricProfileService.recalculate_security_metrics(request.user)",
        content
    )
    
    # delete_email_forever? Is there one in email_view? Let's check.
    # report_false_positive
    content = re.sub(
        r'(def report_false_positive\(request, id\):[\s\S]*?email\.save\(\)[\s\S]*?messages\.success\(request, "Email reported as false positive\. Thank you for your feedback\."\))',
        r"\1\n    AuditService.log(request.user, 'report_false_positive', category='security', metadata={'email_id': id}, request=request)",
        content
    )

    # report_true_positive
    content = re.sub(
        r'(def report_true_positive\(request, id\):[\s\S]*?email\.save\(\)[\s\S]*?messages\.success\(request, "Email reported as phishing\. Thank you for helping improve our system\."\))',
        r"\1\n    AuditService.log(request.user, 'report_true_positive', category='security', metadata={'email_id': id}, request=request)",
        content
    )

    # export_pdf
    content = re.sub(
        r'(def export_pdf\(request, id\):[\s\S]*?pdf_path = generator\.generate\(email\))',
        r"\1\n    AuditService.log(request.user, 'export_pdf', category='system', metadata={'email_id': id}, request=request)",
        content
    )
    
    # settings_view (Settings Changed)
    content = re.sub(
        r'(profile\.save\(\)\n\s+messages\.success\(request, \'Settings updated successfully\.\'\))',
        r"\1\n            AuditService.log(request.user, 'settings_changed', category='system', metadata={'action': 'update_settings'}, request=request)",
        content
    )
    
    # download_attachment
    content = re.sub(
        r'(def download_attachment\(request, id\):[\s\S]*?attachment = get_object_or_404\(EmailAttachment, id=id\))',
        r"\1\n    AuditService.log(request.user, 'download_attachment', category='email', metadata={'attachment_id': id}, request=request)",
        content
    )

    # preview_attachment
    content = re.sub(
        r'(def preview_attachment\(request, id\):[\s\S]*?attachment = get_object_or_404\(EmailAttachment, id=id\))',
        r"\1\n    AuditService.log(request.user, 'preview_attachment', category='email', metadata={'attachment_id': id}, request=request)",
        content
    )

    with open(views_path, 'w') as f:
        f.write(content)

if __name__ == '__main__':
    process_file()
