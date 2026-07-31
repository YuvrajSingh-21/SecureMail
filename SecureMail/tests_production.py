import json
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.models import User
from SecureMail.models import Profile, EmailMessage, AuditLog, Notification
from SecureMail.services.profile_service import ProfileService

class ProductionAuditLogTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='audituser', password='password123')
    
    def test_login_creates_audit_log(self):
        self.client.login(username='audituser', password='password123')
        # Check if login audit log exists
        # NOTE: the subagent is implementing this logic, so this test ensures it works
        self.assertTrue(AuditLog.objects.filter(user=self.user, action__icontains='login').exists())

class ProductionMetricsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='metricsuser', password='password123')
        self.profile = Profile.objects.get(user=self.user)
    
    def test_recalculate_security_metrics(self):
        # Create some emails
        EmailMessage.objects.create(
            user=self.user, sender_email='bad@hacker.com', subject='Phish',
            risk='dangerous', risk_score=90.0, analysis_completed=timezone.now(), folder='inbox'
        )
        EmailMessage.objects.create(
            user=self.user, sender_email='good@friend.com', subject='Hello',
            risk='safe', risk_score=10.0, analysis_completed=timezone.now(), folder='inbox'
        )
        
        ProfileService.recalculate_security_metrics(self.user)
        self.profile.refresh_from_db()
        
        self.assertEqual(self.profile.emails_scanned, 2)
        self.assertEqual(self.profile.threats_blocked, 1)
        self.assertEqual(self.profile.security_score, 50.0) # 100 - avg(90, 10) = 50.0

class ProductionSettingsTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='settingsuser', password='password123')
        self.client.login(username='settingsuser', password='password123')
        
    def test_settings_update(self):
        url = reverse('settings')
        data = {
            'display_name': 'Jane Doe',
            'timezone': 'UTC-05:00 (Eastern Time)',
            'language': 'Spanish (ES)',
            'is_protected': 'on',
            'block_tracking_pixels': 'on',
            'alert_threats': 'on',
            'username': 'settingsuser'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302) # usually redirects or re-renders, let's assume it handles it
        
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Jane')
        self.assertEqual(self.user.last_name, 'Doe')
        
        profile = self.user.profile
        self.assertEqual(profile.timezone, 'UTC-05:00 (Eastern Time)')
        self.assertEqual(profile.language, 'Spanish (ES)')
        self.assertTrue(profile.is_protected)
        self.assertTrue(profile.block_tracking_pixels)

class ProductionMailboxTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='mailuser', password='password123')
        self.client.login(username='mailuser', password='password123')
        
        self.email1 = EmailMessage.objects.create(
            user=self.user, sender_email='bad@hacker.com', subject='Phish',
            risk='dangerous', risk_score=90.0, analysis_completed=timezone.now(), folder='inbox'
        )
    
    def test_delete_email(self):
        url = reverse('delete_email', args=[self.email1.id])
        # This usually expects POST or GET depending on implementation. Let's try POST.
        self.client.post(url)
        self.email1.refresh_from_db()
        self.assertTrue(self.email1.in_trash)
        
        # Check audit log
        self.assertTrue(AuditLog.objects.filter(user=self.user, action__icontains='delete_email').exists())
        
        # Check metrics recalculated
        profile = self.user.profile
        self.assertEqual(profile.emails_scanned, 0) # email is no longer active
