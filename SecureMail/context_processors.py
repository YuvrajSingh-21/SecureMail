from .models import EmailMessage

def sidebar_stats(request):
    if request.user.is_authenticated:
        active_emails = EmailMessage.objects.active(request.user)
        return {
            'unread_count': active_emails.filter(unread=True, in_trash=False).count(),
            'starred_count': active_emails.filter(starred=True, in_trash=False).count(),
            'spam_count': active_emails.filter(folder='SPAM', in_trash=False).count(),
            'trash_count': active_emails.filter(in_trash=True).count(),
            'sent_count': active_emails.filter(folder='SENT').count(),
            'drafts_count': active_emails.filter(folder='DRAFTS').count(),
            'recent_threats': active_emails.filter(category__in=['PHISHING', 'SUSPICIOUS'], unread=True, in_trash=False).order_by('-timestamp')[:3],
            'threat_count': active_emails.filter(category__in=['PHISHING', 'SUSPICIOUS'], unread=True, in_trash=False).count(),
        }
    return {}
