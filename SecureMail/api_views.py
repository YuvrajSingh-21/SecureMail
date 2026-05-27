from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import EmailMessage, Profile
from .serializers import EmailSerializer, ProfileSerializer

class EmailListAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        emails = EmailMessage.objects.filter(user=request.user)
        serializer = EmailSerializer(emails, many=True)
        return Response(serializer.data)

class EmailDetailAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, id):
        try:
            email = EmailMessage.objects.get(id=id, user=request.user)
            serializer = EmailSerializer(email)
            return Response(serializer.data)
        except EmailMessage.DoesNotExist:
            return Response({'error': 'Email not found'}, status=404)

class ProfileAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        profile = request.user.profile
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)

class ReportAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        emails = EmailMessage.objects.filter(user=request.user)
        data = {
            'total': emails.count(),
            'safe': emails.filter(ml_label='SAFE').count(),
            'suspicious': emails.filter(ml_label='SUSPICIOUS').count(),
            'dangerous': emails.filter(ml_label='PHISHING').count(),
            'spam': emails.filter(ml_label='SPAM').count(),
        }
        return Response(data)
