from SecureMail.models import AuditLog

class AuditService:
    @staticmethod
    def log(user, action, category='system', severity='info', metadata=None, request=None):
        ip_address = None
        user_agent = None
        
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            user_agent = request.META.get('HTTP_USER_AGENT')
        
        AuditLog.objects.create(
            user=user,
            action=action,
            category=category,
            severity=severity,
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
