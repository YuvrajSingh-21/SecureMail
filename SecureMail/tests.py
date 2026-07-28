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

class StructuredDataDetectionTest(TestCase):
    def setUp(self):
        from SecureMail.services.gmail_service import GmailService
        from unittest.mock import MagicMock
        mock_account = MagicMock()
        self.service = GmailService(connected_account=mock_account)

    def test_linkedin_invitation_html(self):
        # 1. LinkedIn invitation email with embedded JSON-LD.
        html = """<html><body><script type="application/ld+json">
        { "@context": "http://schema.org", "@type": "EmailMessage" }
        </script></body></html>"""
        self.assertFalse(self.service._is_structured_data(html))

    def test_gmail_action_markup_html(self):
        # 2. Gmail Action Markup email.
        html = """<!DOCTYPE html><html><script type="application/ld+json">
        {"@context":"http://schema.org","@type":"ViewAction"}
        </script></html>"""
        self.assertFalse(self.service._is_structured_data(html))

    def test_pinterest_schema_html(self):
        # 3. Pinterest HTML email with embedded schema.org metadata.
        html = """<div itemscope itemtype="http://schema.org/EmailMessage">Pinterest content</div>"""
        self.assertFalse(self.service._is_structured_data(html))

    def test_standalone_json_ld(self):
        # 4. Pure standalone JSON-LD payload.
        json_ld = '{ "@context": "http://schema.org", "@type": "EmailMessage" }'
        self.assertTrue(self.service._is_structured_data(json_ld))

    def test_standard_html(self):
        # 5. Standard HTML email.
        html = "<html><body>Hello world</body></html>"
        self.assertFalse(self.service._is_structured_data(html))

    def test_plain_text(self):
        # 6. Plain text email.
        text = "Hello world"
        self.assertFalse(self.service._is_structured_data(text))

class ConnectedAccountHistoryIdTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='historytest', password='password123')

    def test_history_id_default_is_none(self):
        from .models import ConnectedAccount
        from django.utils import timezone
        
        account = ConnectedAccount.objects.create(
            user=self.user,
            provider='google',
            email='test@example.com',
            google_id='123456789',
            access_token='fake_access_token',
            token_expiry=timezone.now()
        )
        
        # Ensure the field defaults to None for new users
        self.assertIsNone(account.history_id)
        
        # Ensure the field can handle large strings
        account.history_id = "123456789012345678901234567890"
        account.save()
        account.refresh_from_db()
        self.assertEqual(account.history_id, "123456789012345678901234567890")

class GmailServiceHistoryAPITest(TestCase):
    def setUp(self):
        from SecureMail.services.gmail_service import GmailService
        from unittest.mock import MagicMock
        mock_account = MagicMock()
        
        # Prevent GoogleAuthService from attempting actual OAuth requests
        with patch('SecureMail.services.gmail_service.GoogleAuthService'):
            self.service = GmailService(connected_account=mock_account)
            
        # Mock the underlying Google API Service object
        self.service.service = MagicMock()

    def test_parse_history_response_empty(self):
        delta = self.service.parse_history_response([])
        self.assertEqual(len(delta['messagesAdded']), 0)
        self.assertEqual(len(delta['messagesDeleted']), 0)
        self.assertEqual(len(delta['labelsAdded']), 0)
        self.assertEqual(len(delta['labelsRemoved']), 0)

    def test_parse_history_response_populated(self):
        mock_records = [
            {
                'messagesAdded': [{'message': {'id': 'msg1'}}],
                'messagesDeleted': [{'message': {'id': 'msg2'}}],
                'labelsAdded': [{'message': {'id': 'msg3'}, 'labelIds': ['STARRED']}],
                'labelsRemoved': [{'message': {'id': 'msg4'}, 'labelIds': ['UNREAD']}]
            }
        ]
        delta = self.service.parse_history_response(mock_records)
        self.assertEqual(delta['messagesAdded'][0]['id'], 'msg1')
        self.assertEqual(delta['messagesDeleted'][0]['id'], 'msg2')
        self.assertEqual(delta['labelsAdded'][0]['message']['id'], 'msg3')
        self.assertEqual(delta['labelsRemoved'][0]['labelIds'][0], 'UNREAD')

    def test_get_latest_history_id(self):
        response = {'historyId': '12345'}
        self.assertEqual(self.service.get_latest_history_id(response), '12345')
        self.assertIsNone(self.service.get_latest_history_id({}))

    def test_fetch_history_success_and_pagination(self):
        mock_history = self.service.service.users().history().list.return_value
        
        # Mock two pages of results
        mock_history.execute.side_effect = [
            {'history': [{'id': '1'}], 'nextPageToken': 'token123'},
            {'history': [{'id': '2'}]}
        ]
        
        pages = list(self.service.fetch_history('1000'))
        
        self.assertEqual(len(pages), 2)
        self.assertEqual(pages[0]['history'][0]['id'], '1')
        self.assertEqual(pages[1]['history'][0]['id'], '2')

    def test_fetch_history_expired(self):
        from googleapiclient.errors import HttpError
        from SecureMail.services.gmail_service import HistoryExpiredError
        import httplib2
        
        mock_history = self.service.service.users().history().list.return_value
        mock_history.execute.side_effect = HttpError(
            httplib2.Response({'status': 404}), b'History ID not found'
        )
        
        with self.assertRaises(HistoryExpiredError):
            list(self.service.fetch_history('expired_id'))

    def test_fetch_history_invalid(self):
        from googleapiclient.errors import HttpError
        from SecureMail.services.gmail_service import HistoryInvalidError
        import httplib2
        
        mock_history = self.service.service.users().history().list.return_value
        mock_history.execute.side_effect = HttpError(
            httplib2.Response({'status': 500}), b'Internal Error'
        )
        
        with self.assertRaises(HistoryInvalidError):
            list(self.service.fetch_history('some_id'))

class SyncManagerBootstrapTest(TestCase):
    def setUp(self):
        from SecureMail.models import ConnectedAccount
        from django.utils import timezone
        self.user = User.objects.create_user(username='syncmanager_test', password='password123')
        self.account = ConnectedAccount.objects.create(
            user=self.user,
            provider='google',
            email='test@example.com',
            google_id='123456789',
            access_token='fake',
            token_expiry=timezone.now()
        )
        
    @patch('SecureMail.services.sync_manager.GmailService')
    def test_bootstrap_on_success(self, mock_gmail_service_class):
        from SecureMail.services.sync_manager import SyncManager
        from SecureMail.models import SyncJob
        
        # Setup mock GmailService behavior
        mock_gmail = mock_gmail_service_class.return_value
        mock_gmail.fetch_all_message_ids.return_value = []
        mock_gmail.get_profile.return_value = {'historyId': '99999'}
        
        manager = SyncManager(self.user)
        # Inject the mocked service manually to bypass auth fetching issues
        manager.gmail = mock_gmail
        
        job = SyncJob.objects.create(user=self.user, status='RUNNING')
        manager._execute_sync(job, limit=10)
        
        self.account.refresh_from_db()
        self.assertEqual(self.account.history_id, '99999')
        self.assertEqual(job.status, 'COMPLETED')

    @patch('SecureMail.services.sync_manager.GmailService')
    def test_bootstrap_skipped_if_already_set(self, mock_gmail_service_class):
        from SecureMail.services.sync_manager import SyncManager
        from SecureMail.models import SyncJob
        
        self.account.history_id = '11111'
        self.account.save()
        
        mock_gmail = mock_gmail_service_class.return_value
        mock_gmail.fetch_all_message_ids.return_value = []
        mock_gmail.get_profile.return_value = {'historyId': '99999'} # Should not overwrite
        
        manager = SyncManager(self.user)
        manager.gmail = mock_gmail
        
        job = SyncJob.objects.create(user=self.user, status='RUNNING')
        manager._execute_sync(job, limit=10)
        
        self.account.refresh_from_db()
        self.assertEqual(self.account.history_id, '11111')
        mock_gmail.get_profile.assert_not_called()

    @patch('SecureMail.services.sync_manager.GmailService')
    def test_bootstrap_does_not_fail_sync_on_error(self, mock_gmail_service_class):
        from SecureMail.services.sync_manager import SyncManager
        from SecureMail.models import SyncJob
        
        mock_gmail = mock_gmail_service_class.return_value
        mock_gmail.fetch_all_message_ids.return_value = []
        mock_gmail.get_profile.side_effect = Exception("Google API Down")
        
        manager = SyncManager(self.user)
        manager.gmail = mock_gmail
        
        job = SyncJob.objects.create(user=self.user, status='RUNNING')
        manager._execute_sync(job, limit=10) # Should swallow exception and not crash
        
        self.account.refresh_from_db()
        self.assertIsNone(self.account.history_id)
        self.assertEqual(job.status, 'COMPLETED') # Sync still completes!
