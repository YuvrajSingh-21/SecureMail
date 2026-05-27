from ..models import EmailMessage, Profile, Notification

class BaseRepository:
    model = None

    def get_by_id(self, id):
        return self.model.objects.get(id=id)

    def all(self):
        return self.model.objects.all()

class EmailRepository(BaseRepository):
    model = EmailMessage

    def get_user_inbox(self, user):
        return EmailMessage.objects.inbox(user)

    def get_user_starred(self, user):
        return EmailMessage.objects.starred(user)

    def get_user_trash(self, user):
        return EmailMessage.objects.trash(user)

    def get_user_email(self, user, id):
        return EmailMessage.objects.get(user=user, id=id)

class ProfileRepository(BaseRepository):
    model = Profile

    def get_by_user(self, user):
        return Profile.objects.get(user=user)

class NotificationRepository(BaseRepository):
    model = Notification

    def get_unread_for_user(self, user):
        return Notification.objects.filter(user=user, read=False).order_by('-created_at')
