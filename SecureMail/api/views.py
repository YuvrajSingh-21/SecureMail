from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from ..services.business_logic import EmailService, ProfileService
from .serializers import EmailSerializer, ProfileSerializer

class EmailListAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        service = EmailService()
        emails = service.list_inbox(request.user)
        serializer = EmailSerializer(emails, many=True)
        return Response(serializer.data)

class EmailDetailAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, id):
        service = EmailService()
        try:
            email = service.get_email_detail(request.user, id)
            serializer = EmailSerializer(email)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=404)

class MarkReadAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, id):
        service = EmailService()
        try:
            email = service.repository.get_user_email(request.user, id)
            if email.unread:
                email.unread = False
                email.save()
                
                if email.gmail_message_id:
                    try:
                        from ..services.gmail_service import GmailService
                        from ..models import ConnectedAccount
                        account = ConnectedAccount.objects.get(user=request.user)
                        GmailService(account).mark_as_read(email.gmail_message_id)
                    except Exception as e:
                        pass
            return Response({'status': 'success'})
        except Exception as e:
            return Response({'error': str(e)}, status=404)

class ProfileAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        service = ProfileService()
        profile = service.repository.get_by_user(request.user)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)
