from rest_framework import serializers
from django.contrib.auth.models import User
from ..models import Profile, EmailMessage, ThreatIndicator

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
    analysis = serializers.SerializerMethodField()
    
    class Meta:
        model = EmailMessage
        fields = [
            'id', 'sender_email', 'sender_name', 'recipient_email', 
            'subject', 'body', 'timestamp', 'unread', 'starred', 
            'indicators', 'analysis', 'risk'
        ]

    def get_analysis(self, obj):
        try:
            from ..services.risk_engine import RiskEngine
            engine = RiskEngine()
            report = obj.analysis.detailed_report
            return engine.normalize_payload(report)
        except:
            return {}
