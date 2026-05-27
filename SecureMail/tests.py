import json
from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.contrib.auth.models import User
from .models import EmailMessage, RiskScore, ThreatAnalysis
from .services.business_logic import EmailService
from .services.virustotal_service import VirusTotalService
from .services.safe_browsing_service import SafeBrowsingService
from .services.risk_engine import RiskEngine
from .services.email_pipeline import EmailPipeline

class EmailServiceTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password123')
        # Patch external services before initializing EmailService
        self.patch_vt = patch('SecureMail.services.email_pipeline.VirusTotalService')
        self.patch_gsb = patch('SecureMail.services.email_pipeline.SafeBrowsingService')
        
        self.mock_vt_class = self.patch_vt.start()
        self.mock_gsb_class = self.patch_gsb.start()
        
        self.service = EmailService()

    def tearDown(self):
        self.patch_vt.stop()
        self.patch_gsb.stop()

    def test_list_inbox(self):
        email = EmailMessage.objects.create(
            user=self.user,
            sender_email='sender@example.com',
            recipient_email='testuser@example.com',
            subject='Test Email',
            body='This is a test email body'
        )
        inbox = self.service.list_inbox(self.user)
        self.assertEqual(inbox.count(), 1)
        self.assertEqual(inbox.first(), email)

class VirusTotalServiceTest(TestCase):
    def setUp(self):
        self.service = VirusTotalService()
        self.service.api_key = "test_key"

    @patch('requests.get')
    def test_scan_hash_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "test_id"}}
        mock_get.return_value = mock_response
        result = self.service.scan_hash("fake_hash")
        self.assertEqual(result["data"]["id"], "test_id")

class SafeBrowsingServiceTest(TestCase):
    def setUp(self):
        self.service = SafeBrowsingService()
        self.service.api_key = "test_key"

    @patch('requests.post')
    def test_check_urls_malicious(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "matches": [
                {
                    "threatType": "MALWARE",
                    "threat": {"url": "http://malicious.com"}
                }
            ]
        }
        mock_post.return_value = mock_response
        result = self.service.check_urls(["http://malicious.com"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["threatType"], "MALWARE")

class RiskEngineTest(TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_calculate_risk_safe(self):
        result = self.engine.calculate_risk(
            gemini_result=None,
            link_results=[],
            attachment_results=[],
            sender_email="john@trusted-company.com"
        )
        self.assertEqual(result['category'], 'safe')

    def test_reputation_check(self):
        score_safe = self.engine._check_reputation("support@amazon.com")
        score_bad = self.engine._check_reputation("security@amaz0n-verify.net")
        self.assertEqual(score_safe, 0)
        self.assertGreater(score_bad, 50)

class EmailPipelineTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='pipelineuser', password='password123')
        self.email = EmailMessage.objects.create(
            user=self.user,
            sender_email='sender@example.com',
            recipient_email='user@example.com',
            subject='Pipeline Test',
            body='Check this link: http://test.com'
        )

    @patch('SecureMail.services.email_pipeline.SafeBrowsingService')
    @patch('SecureMail.services.email_pipeline.VirusTotalService')
    def test_pipeline_run_success(self, mock_vt, mock_gsb):
        # Setup mocks
        mock_gsb_instance = mock_gsb.return_value
        mock_gsb_instance.check_urls.return_value = []
        
        pipeline = EmailPipeline()
        result = pipeline.run(self.email.id)
        
        self.assertTrue(result)
        self.assertTrue(RiskScore.objects.filter(email=self.email).exists())
        self.assertTrue(ThreatAnalysis.objects.filter(email=self.email).exists())
