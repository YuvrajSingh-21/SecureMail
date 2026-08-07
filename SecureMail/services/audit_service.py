import logging
from SecureMail.models import AuditLog
from SecureMail.utils import get_client_ip

logger = logging.getLogger(__name__)

class AuditService:
    @staticmethod
    def log(user, action, category='system', severity='info', metadata=None, request=None):
        """
        Record a security/audit event.
        Extracts and normalizes client IP via get_client_ip() to guarantee compatibility
        with PostgreSQL inet / GenericIPAddressField columns.
        """
        try:
            ip_address = get_client_ip(request) if request else None
            user_agent = request.META.get('HTTP_USER_AGENT') if request else None
            
            return AuditLog.objects.create(
                user=user,
                action=action,
                category=category,
                severity=severity,
                metadata=metadata or {},
                ip_address=ip_address,
                user_agent=user_agent
            )
        except Exception as e:
            username = getattr(user, 'username', 'anonymous') if user else 'anonymous'
            logger.error(f"AuditService.log failed for user {username}, action '{action}': {str(e)}", exc_info=True)
            return None
