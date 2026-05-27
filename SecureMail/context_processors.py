from .models import EmailMessage

def sidebar_stats(request):
    if request.user.is_authenticated:
        emails = EmailMessage.objects.filter(user=request.user)
        return {
            'unread_count': emails.filter(unread=True, in_trash=False).count(),
            'starred_count': emails.filter(starred=True, in_trash=False).count(),
            'spam_count': emails.filter(folder='SPAM', in_trash=False).count(),
            'trash_count': emails.filter(in_trash=True).count(),
            'sent_count': emails.filter(folder='SENT').count(),
            'drafts_count': emails.filter(folder='DRAFTS').count(),
        }
    return {}
