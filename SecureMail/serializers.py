from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile, EmailMessage, ThreatAnalysis, ThreatIndicator, Attachment

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']

class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = Profile
        fields = ['user', 'security_score', 'emails_scanned', 'threats_blocked', 'is_protected']

class ThreatIndicatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatIndicator
        fields = ['description', 'severity']

class EmailSerializer(serializers.ModelSerializer):
    indicators = ThreatIndicatorSerializer(many=True, read_only=True)
    analysis_summary = serializers.CharField(source='analysis.summary', read_only=True, allow_null=True)
    
    class Meta:
        model = EmailMessage
        fields = [
            'id', 'sender_email', 'sender_name', 'recipient_email', 
            'subject', 'body', 'timestamp', 'unread', 'starred', 
            'indicators',
            'ml_label', 'ml_score', 'sender_reputation', 'analysis_reasons',
            'analysis_summary'
        ]
