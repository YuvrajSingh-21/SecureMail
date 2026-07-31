import re

def update_pipeline():
    path = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/services/email_pipeline.py'
    with open(path, 'r') as f:
        content = f.read()

    old_func = """    def _update_user_profile(self, email):
        from django.db.models import Avg
        profile = email.user.profile
        active_emails = EmailMessage.objects.active(email.user)
        
        profile.emails_scanned = active_emails.filter(analysis_completed__isnull=False).count()
        profile.threats_blocked = active_emails.filter(risk='dangerous').count()
        
        avg_risk = active_emails.filter(analysis_completed__isnull=False).order_by('-timestamp')[:50].aggregate(Avg('risk_score'))['risk_score__avg'] or 0
        profile.security_score = max(0, 100 - avg_risk)
        profile.save()"""

    new_func = """    def _update_user_profile(self, email):
        from .profile_service import ProfileService as MetricProfileService
        from SecureMail.models import Notification
        
        MetricProfileService.recalculate_security_metrics(email.user)
        
        try:
            profile = email.user.profile
            if email.risk == 'dangerous' and profile.alert_threats:
                Notification.objects.create(
                    user=email.user,
                    title="Phishing Threat Detected",
                    message=f"A dangerous email '{email.subject}' was detected.",
                    type='threat'
                )
        except Exception as e:
            logger.error(f"Failed to create notification: {str(e)}")"""

    if old_func in content:
        content = content.replace(old_func, new_func)
    else:
        print("OLD FUNC NOT FOUND")

    with open(path, 'w') as f:
        f.write(content)

update_pipeline()
