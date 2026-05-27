from ..services.business_logic import EmailService
from ..models import EmailMessage

def analyze_email_task(email_id):
    """
    Mock Celery task for asynchronous email analysis.
    """
    try:
        email = EmailMessage.objects.get(id=email_id)
        service = EmailService()
        service.process_new_email(email)
        return True
    except EmailMessage.DoesNotExist:
        return False
