"""
CSRF Regression Tests for SecureMail
Covers: delete_email, toggle_star, sync_gmail
Phase 7 of the CSRF remediation plan.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.models import User
from unittest.mock import patch, MagicMock
from SecureMail.models import EmailMessage, AuditLog


class DeleteEmailCSRFTest(TestCase):
    """Tests confirming delete_email is POST-only and CSRF-protected."""

    def setUp(self):
        self.user = User.objects.create_user(username='del_user', password='pass123')
        self.other_user = User.objects.create_user(username='other_del', password='pass123')
        self.email = EmailMessage.objects.create(
            user=self.user,
            sender_email='attacker@evil.com',
            subject='Test',
            folder='inbox',
        )
        self.url = reverse('delete_email', args=[self.email.id])
        # Standard client (no CSRF enforcement — simulates logged-in browser)
        self.client = Client()
        self.client.login(username='del_user', password='pass123')
        # Strict client (enforces CSRF — simulates cross-site attacker)
        self.strict_client = Client(enforce_csrf_checks=True)
        self.strict_client.login(username='del_user', password='pass123')

    # 1. Authenticated GET → 405
    def test_get_returns_405(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    # 2. GET does not trash the email
    def test_get_does_not_trash_email(self):
        self.client.get(self.url)
        self.email.refresh_from_db()
        self.assertFalse(self.email.in_trash)

    # 3. GET does not permanently delete the email
    def test_get_does_not_permanently_delete_email(self):
        self.client.get(self.url)
        self.assertTrue(EmailMessage.objects.filter(id=self.email.id).exists())

    # 4. POST without CSRF token → 403
    def test_post_without_csrf_returns_403(self):
        response = self.strict_client.post(self.url)
        self.assertEqual(response.status_code, 403)

    # 5. POST with valid CSRF → succeeds (moves to trash)
    def test_valid_post_moves_email_to_trash(self):
        response = self.client.post(self.url)
        self.assertIn(response.status_code, [200, 302])
        self.email.refresh_from_db()
        self.assertTrue(self.email.in_trash)

    # 6. Normal email → move to Trash (in_trash=True, not deleted)
    def test_normal_email_moves_to_trash_not_deleted(self):
        self.client.post(self.url)
        self.assertTrue(EmailMessage.objects.filter(id=self.email.id).exists())
        self.email.refresh_from_db()
        self.assertTrue(self.email.in_trash)

    # 7. Email already in Trash → permanently delete
    def test_trash_email_is_permanently_deleted(self):
        self.email.in_trash = True
        self.email.save()
        self.client.post(self.url)
        self.assertFalse(EmailMessage.objects.filter(id=self.email.id).exists())

    # 8. User cannot delete another user's email
    def test_cannot_delete_other_users_email(self):
        other_email = EmailMessage.objects.create(
            user=self.other_user,
            sender_email='a@b.com',
            subject='Other',
            folder='inbox',
        )
        other_url = reverse('delete_email', args=[other_email.id])
        response = self.client.post(other_url)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(EmailMessage.objects.filter(id=other_email.id).exists())


class ToggleStarCSRFTest(TestCase):
    """Tests confirming toggle_star is POST-only and CSRF-protected."""

    def setUp(self):
        self.user = User.objects.create_user(username='star_user', password='pass123')
        self.other_user = User.objects.create_user(username='other_star', password='pass123')
        self.email = EmailMessage.objects.create(
            user=self.user,
            sender_email='test@example.com',
            subject='Star me',
            folder='inbox',
            starred=False,
        )
        self.url = reverse('toggle_star', args=[self.email.id])
        self.client = Client()
        self.client.login(username='star_user', password='pass123')
        self.strict_client = Client(enforce_csrf_checks=True)
        self.strict_client.login(username='star_user', password='pass123')

    # 1. Authenticated GET → 405
    def test_get_returns_405(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    # 2. GET cannot change starred state
    def test_get_does_not_change_starred_state(self):
        self.client.get(self.url)
        self.email.refresh_from_db()
        self.assertFalse(self.email.starred)

    # 3. POST without CSRF token → 403
    def test_post_without_csrf_returns_403(self):
        response = self.strict_client.post(self.url)
        self.assertEqual(response.status_code, 403)

    # 4. Valid POST toggles star (False → True)
    def test_valid_post_toggles_star_on(self):
        self.client.post(self.url)
        self.email.refresh_from_db()
        self.assertTrue(self.email.starred)

    # 5. Valid POST toggles star again (True → False)
    def test_valid_post_toggles_star_off(self):
        self.email.starred = True
        self.email.save()
        self.client.post(self.url)
        self.email.refresh_from_db()
        self.assertFalse(self.email.starred)

    # 6. Another user's email cannot be star-toggled
    def test_cannot_toggle_other_users_email(self):
        other_email = EmailMessage.objects.create(
            user=self.other_user,
            sender_email='a@b.com',
            subject='Other',
            folder='inbox',
            starred=False,
        )
        other_url = reverse('toggle_star', args=[other_email.id])
        self.client.post(other_url)
        other_email.refresh_from_db()
        # star state must not change for another user's email
        self.assertFalse(other_email.starred)


class SyncGmailCSRFTest(TestCase):
    """Tests confirming sync_gmail is POST-only and CSRF-protected."""

    def setUp(self):
        self.user = User.objects.create_user(username='sync_user', password='pass123')
        self.url = reverse('sync_gmail')
        self.client = Client()
        self.client.login(username='sync_user', password='pass123')
        self.strict_client = Client(enforce_csrf_checks=True)
        self.strict_client.login(username='sync_user', password='pass123')

    # 1. GET → 405
    def test_get_returns_405(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    # 2. GET cannot create a SyncJob (no state change)
    @patch('SecureMail.views.SyncManager')
    def test_get_cannot_start_sync(self, MockManager):
        self.client.get(self.url)
        MockManager.assert_not_called()

    # 3. POST without CSRF token → 403
    def test_post_without_csrf_returns_403(self):
        response = self.strict_client.post(self.url)
        self.assertEqual(response.status_code, 403)

    # 4. Valid POST reaches sync logic
    @patch('SecureMail.views.SyncManager')
    def test_valid_post_calls_sync_manager(self, MockManager):
        mock_instance = MagicMock()
        mock_instance.start_sync.return_value = MagicMock()
        MockManager.return_value = mock_instance
        response = self.client.post(self.url)
        mock_instance.start_sync.assert_called_once()
        self.assertIn(response.status_code, [200, 302])

    # 5. auto=1 POST parameter is read from POST body (not GET query string)
    @patch('SecureMail.views.SyncManager')
    def test_auto_sync_via_post_body(self, MockManager):
        mock_instance = MagicMock()
        mock_instance.start_sync.return_value = MagicMock()
        MockManager.return_value = mock_instance
        response = self.client.post(self.url, data={'auto': '1'},
                                    content_type='application/x-www-form-urlencoded',
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertIn(response.status_code, [200, 302])
        mock_instance.start_sync.assert_called_once()

    # 6. full=true POST parameter triggers full sync
    @patch('SecureMail.views.SyncManager')
    def test_full_sync_via_post_body(self, MockManager):
        mock_instance = MagicMock()
        mock_instance.start_sync.return_value = MagicMock()
        MockManager.return_value = mock_instance
        self.client.post(self.url, data={'all': 'true'})
        mock_instance.start_sync.assert_called_once_with(full_sync=True)

    # 7. Duplicate-job protection: running SyncJob prevents new start when auto=1
    @patch('SecureMail.views.SyncManager')
    def test_running_job_blocks_auto_sync(self, MockManager):
        from SecureMail.models import SyncJob
        SyncJob.objects.create(user=self.user, status='RUNNING')
        mock_instance = MagicMock()
        MockManager.return_value = mock_instance
        response = self.client.post(self.url, data={'auto': '1'},
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        import json
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'already_running')
        mock_instance.start_sync.assert_not_called()
