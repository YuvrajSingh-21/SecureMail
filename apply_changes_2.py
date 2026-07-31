import os

def patch_views():
    views_path = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/views.py'
    with open(views_path, 'r') as f:
        lines = f.readlines()
        
    for i, line in enumerate(lines):
        # 4. delete_email
        if 'def delete_email(request, id):' in line:
            # find where messages.success(request, "Email deleted successfully.") is
            for j in range(i, i+30):
                if 'messages.success(request, "Email deleted successfully.")' in lines[j]:
                    lines.insert(j, "    MetricProfileService.recalculate_security_metrics(request.user)\n")
                    lines.insert(j, f"    AuditService.log(request.user, 'delete_email', category='email', metadata={{'email_id': id}}, request=request)\n")
                    break

        # 5. report_false_positive
        if 'def report_false_positive(request, id):' in line:
            for j in range(i, i+30):
                if 'messages.success(request, "Email reported as false positive. Thank you for your feedback.")' in lines[j]:
                    lines.insert(j, f"    AuditService.log(request.user, 'report_false_positive', category='security', metadata={{'email_id': id}}, request=request)\n")
                    break

        # 6. report_true_positive
        if 'def report_true_positive(request, id):' in line:
            for j in range(i, i+30):
                if 'messages.success(request, "Email reported as phishing. Thank you for helping improve our system.")' in lines[j]:
                    lines.insert(j, f"    AuditService.log(request.user, 'report_true_positive', category='security', metadata={{'email_id': id}}, request=request)\n")
                    break

        # 7. export_pdf
        if 'def export_pdf(request, id):' in line:
            for j in range(i, i+30):
                if 'pdf_path = generator.generate(email)' in lines[j]:
                    lines.insert(j+1, f"    AuditService.log(request.user, 'export_pdf', category='system', metadata={{'email_id': id}}, request=request)\n")
                    break
        
        # 8. settings_view
        if 'def settings_view(request):' in line:
            for j in range(i, i+200):
                if 'messages.success(request, "Settings updated successfully.")' in lines[j]:
                    lines.insert(j, f"            AuditService.log(request.user, 'settings_changed', category='system', metadata={{'action': 'update_settings'}}, request=request)\n")
                    break

        # 9. download_attachment
        if 'def download_attachment(request, id):' in line:
            for j in range(i, i+10):
                if 'att = get_object_or_404(Attachment, id=id, email__user=request.user)' in lines[j]:
                    lines.insert(j+1, f"    AuditService.log(request.user, 'download_attachment', category='email', metadata={{'attachment_id': id}}, request=request)\n")
                    break

        # 10. preview_attachment
        if 'def preview_attachment(request, id):' in line:
            for j in range(i, i+10):
                if 'att = get_object_or_404(Attachment, id=id, email__user=request.user)' in lines[j]:
                    lines.insert(j+1, f"    AuditService.log(request.user, 'preview_attachment', category='email', metadata={{'attachment_id': id}}, request=request)\n")
                    break
                    
        # 11. Remove mock data in profile_view
        if 'def profile_view(request):' in line:
            for j in range(i, i+30):
                if 'activity = [' in lines[j]:
                    # delete next 5 lines
                    lines[j] = "    activity = AuditLog.objects.filter(user=request.user).order_by('-timestamp')[:10]\n"
                    lines[j+1] = ""
                    lines[j+2] = ""
                    lines[j+3] = ""
                    lines[j+4] = ""
                    lines[j+5] = ""
                    break

    with open(views_path, 'w') as f:
        f.writelines(lines)

patch_views()
