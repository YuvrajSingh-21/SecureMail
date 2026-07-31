from django.db.models import Avg
from SecureMail.models import EmailMessage, Profile

class ProfileService:
    @staticmethod
    def recalculate_security_metrics(user):
        try:
            profile = user.profile
        except Profile.DoesNotExist:
            profile = Profile.objects.create(user=user)

        # 1. Count all emails in active(user) with analysis_completed__isnull=False
        scanned_count = EmailMessage.objects.active(user).filter(analysis_completed__isnull=False).count()
        profile.emails_scanned = scanned_count
        
        # 2. Count threats: active(user).filter(risk='dangerous').count()
        threats_count = EmailMessage.objects.active(user).filter(risk='dangerous').count()
        profile.threats_blocked = threats_count
        
        # 3. Calculate score
        recent_ids = EmailMessage.objects.active(user).order_by('-timestamp').values_list('id', flat=True)[:50]
        avg_dict = EmailMessage.objects.filter(id__in=list(recent_ids)).aggregate(avg_score=Avg('risk_score'))
        avg = avg_dict['avg_score'] or 0
        profile.security_score = max(0.0, 100.0 - float(avg))
        
        profile.save(update_fields=['emails_scanned', 'threats_blocked', 'security_score'])
