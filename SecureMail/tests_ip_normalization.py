import ipaddress
from unittest.mock import patch, MagicMock
from django.test import TestCase, RequestFactory, Client
from django.contrib.auth.models import User
from django.utils import timezone
from SecureMail.models import AuditLog, ConnectedAccount, SyncJob
from SecureMail.utils import normalize_ip_address, get_client_ip
from SecureMail.services.audit_service import AuditService
from SecureMail.views import sync_gmail
from SecureMail.google_auth_views import google_callback

class IPNormalizationUnitTests(TestCase):
    def test_ipv4_with_port(self):
        self.assertEqual(normalize_ip_address("157.48.193.106:47818"), "157.48.193.106")
        self.assertEqual(normalize_ip_address("127.0.0.1:8000"), "127.0.0.1")
        self.assertEqual(normalize_ip_address("192.168.1.1:443"), "192.168.1.1")

    def test_clean_ipv4_unchanged(self):
        self.assertEqual(normalize_ip_address("157.48.193.106"), "157.48.193.106")
        self.assertEqual(normalize_ip_address("10.0.0.1"), "10.0.0.1")
        self.assertEqual(normalize_ip_address("127.0.0.1"), "127.0.0.1")

    def test_clean_ipv6_unchanged(self):
        self.assertEqual(normalize_ip_address("2001:db8::1"), "2001:db8::1")
        self.assertEqual(normalize_ip_address("::1"), "::1")
        self.assertEqual(normalize_ip_address("fe80::1ff:fe23:4567:890a"), "fe80::1ff:fe23:4567:890a")

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(normalize_ip_address("[2001:db8::1]:8080"), "2001:db8::1")
        self.assertEqual(normalize_ip_address("[::1]:443"), "::1")
        self.assertEqual(normalize_ip_address("[2001:db8:85a3::8a2e:370:7334]:47818"), "2001:db8:85a3::8a2e:370:7334")

    def test_bracketed_ipv6_without_port(self):
        self.assertEqual(normalize_ip_address("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(normalize_ip_address("[::1]"), "::1")

    def test_invalid_ips(self):
        self.assertIsNone(normalize_ip_address(None))
        self.assertIsNone(normalize_ip_address(""))
        self.assertIsNone(normalize_ip_address("   "))
        self.assertIsNone(normalize_ip_address("unknown"))
        self.assertIsNone(normalize_ip_address("invalid_ip"))
        self.assertIsNone(normalize_ip_address("999.999.999.999"))
        self.assertIsNone(normalize_ip_address("157.48.193.106:port"))
        self.assertIsNone(normalize_ip_address("157.48.193.106:9999999"))


class ClientIPExtractionTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_x_forwarded_for_with_port_and_multiple_ips(self):
        request = self.factory.get('/', HTTP_X_FORWARDED_FOR='157.48.193.106:47818, 10.0.0.1')
        self.assertEqual(get_client_ip(request), '157.48.193.106')

    def test_x_forwarded_for_with_invalid_first_hop(self):
        request = self.factory.get('/', HTTP_X_FORWARDED_FOR='unknown, 157.48.193.106:47818')
        self.assertEqual(get_client_ip(request), '157.48.193.106')

    def test_remote_addr_with_port(self):
        request = self.factory.get('/', REMOTE_ADDR='157.48.193.106:47818')
        self.assertEqual(get_client_ip(request), '157.48.193.106')

    def test_remote_addr_with_bracketed_ipv6_port(self):
        request = self.factory.get('/', REMOTE_ADDR='[2001:db8::1]:47818')
        self.assertEqual(get_client_ip(request), '2001:db8::1')

    def test_audit_service_persists_valid_ip(self):
        user = User.objects.create_user(username='test_audit_user', email='audit@secureamail.me')
        request = self.factory.get('/', REMOTE_ADDR='157.48.193.106:47818')
        
        log = AuditService.log(user, 'test_action', category='auth', request=request)
        self.assertIsNotNone(log)
        self.assertEqual(log.ip_address, '157.48.193.106')

        # Verify retrieved from DB
        db_log = AuditLog.objects.get(id=log.id)
        self.assertEqual(db_log.ip_address, '157.48.193.106')


class EndToEndRegressionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='syncuser', email='syncuser@secureamail.me', password='password123')

    @patch('SecureMail.services.sync_manager.SyncManager.start_sync')
    def test_sync_gmail_with_port_in_remote_addr_does_not_500(self, mock_start_sync):
        client = Client()
        client.force_login(self.user)
        
        mock_job = MagicMock()
        mock_job.id = 1
        mock_start_sync.return_value = mock_job
        
        response = client.post('/sync/', {'all': 'false'}, REMOTE_ADDR='157.48.193.106:47818')
        self.assertIn(response.status_code, [200, 302])
        
        # Verify AuditLog was saved with normalized IP
        log = AuditLog.objects.filter(user=self.user, action='mailbox_sync').latest('created_at')
        self.assertEqual(log.ip_address, '157.48.193.106')

    @patch('SecureMail.services.sync_manager.SyncManager.start_sync')
    @patch('SecureMail.google_auth_views.GoogleAuthService')
    @patch('SecureMail.google_auth_views.build')
    def test_google_callback_new_user_with_port_in_remote_addr(self, mock_build, mock_google_auth_cls, mock_start_sync):
        client = Client()
        
        mock_service = MagicMock()
        mock_google_auth_cls.return_value = mock_service
        mock_service.get_credentials_from_code.return_value = MagicMock()
        mock_service.update_or_create_connected_account.return_value = MagicMock()
        
        mock_oauth_service = MagicMock()
        mock_build.return_value = mock_oauth_service
        mock_oauth_service.userinfo().get().execute.return_value = {'email': 'newuser@secureamail.me'}
        
        session = client.session
        session['oauth_state'] = 'teststate123'
        session['oauth_code_verifier'] = 'testverifier123'
        session.save()
        
        response = client.get(
            '/auth/google/callback/?state=teststate123&code=testcode123',
            REMOTE_ADDR='157.48.193.106:47818'
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/inbox/')
        
        # Check user created and logged
        user = User.objects.get(email='newuser@secureamail.me')
        log = AuditLog.objects.filter(user=user, action='login').latest('created_at')
        self.assertEqual(log.ip_address, '157.48.193.106')

    @patch('SecureMail.google_auth_views.GoogleAuthService')
    @patch('SecureMail.google_auth_views.build')
    def test_google_callback_existing_user_connect_gmail_with_port_in_remote_addr(self, mock_build, mock_google_auth_cls):
        client = Client()
        client.force_login(self.user)
        
        mock_service = MagicMock()
        mock_google_auth_cls.return_value = mock_service
        mock_service.get_credentials_from_code.return_value = MagicMock()
        mock_service.update_or_create_connected_account.return_value = MagicMock()
        
        mock_oauth_service = MagicMock()
        mock_build.return_value = mock_oauth_service
        mock_oauth_service.userinfo().get().execute.return_value = {'email': 'syncuser@secureamail.me'}
        
        session = client.session
        session['oauth_state'] = 'teststate456'
        session['oauth_code_verifier'] = 'testverifier456'
        session.save()
        
        response = client.get(
            '/auth/google/callback/?state=teststate456&code=testcode456',
            REMOTE_ADDR='157.48.193.106:47818'
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/settings/')
        
        log = AuditLog.objects.filter(user=self.user, action='connect_gmail').latest('created_at')
        self.assertEqual(log.ip_address, '157.48.193.106')
