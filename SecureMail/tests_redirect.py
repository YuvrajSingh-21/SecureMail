"""
Open Redirect Regression Tests for SecureMail.

Covers:
  - safe_redirect helper (unit tests, isolated)
  - delete_email endpoint redirect behavior
  - toggle_star endpoint redirect behavior
  - inbox bulk-action endpoint redirect behavior

All tests use Django's test Client with enforce_csrf_checks=False so
that they reach the redirect logic rather than hitting CSRF rejection.
The CSRF properties themselves are already covered in tests_csrf.py.
"""
from django.test import TestCase, Client, RequestFactory
from django.urls import reverse
from django.contrib.auth.models import User
from SecureMail.models import EmailMessage
from SecureMail.utils import safe_redirect


# ---------------------------------------------------------------------------
# Helper: create a minimal GET-like request for testing safe_redirect() alone
# ---------------------------------------------------------------------------

class SafeRedirectHelperTest(TestCase):
    """Unit-tests for safe_redirect() in isolation using RequestFactory."""

    def setUp(self):
        self.factory = RequestFactory()

    def _get_request(self, secure=False):
        """Return a minimal POST request object (method doesn't matter for helper)."""
        req = self.factory.get('/', secure=secure)
        # SERVER_NAME is 'testserver' for Django RequestFactory
        return req

    def _location(self, response):
        return response.get('Location', '')

    # A. Relative internal URL → allowed
    def test_relative_internal_url_allowed(self):
        req = self._get_request()
        resp = safe_redirect(req, '/inbox/', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self._location(resp), '/inbox/')

    # B. Same-host absolute URL → allowed (HTTP request)
    def test_same_host_absolute_url_allowed(self):
        req = self._get_request()
        resp = safe_redirect(req, 'http://testserver/inbox/', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self._location(resp), 'http://testserver/inbox/')

    # C. External HTTPS → rejected → fallback
    def test_external_https_rejected(self):
        req = self._get_request()
        resp = safe_redirect(req, 'https://evil.example/phishing', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.example', self._location(resp))
        self.assertIn('/inbox/', self._location(resp))

    # D. External HTTP → rejected → fallback
    def test_external_http_rejected(self):
        req = self._get_request()
        resp = safe_redirect(req, 'http://evil.example/phishing', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.example', self._location(resp))

    # E. Protocol-relative external → rejected
    def test_protocol_relative_external_rejected(self):
        req = self._get_request()
        resp = safe_redirect(req, '//evil.example/phishing', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.example', self._location(resp))

    # F. Pseudo-path that passes url_has_allowed_host_and_scheme but fails redirect() → fallback via exception guard
    def test_malformed_colon_path_falls_back(self):
        req = self._get_request()
        # ':::not a url:::' is treated as relative by the URL parser but
        # cannot be resolved by Django's redirect(); the exception guard
        # in safe_redirect must catch it and fall back.
        resp = safe_redirect(req, ':::not a url:::', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', self._location(resp))

    # G. Empty / missing referer → fallback
    def test_empty_referer_uses_fallback(self):
        req = self._get_request()
        resp = safe_redirect(req, '', fallback='inbox')
        self.assertIn('/inbox/', self._location(resp))

    def test_none_referer_uses_fallback(self):
        req = self._get_request()
        resp = safe_redirect(req, None, fallback='inbox')
        self.assertIn('/inbox/', self._location(resp))

    # H. HTTPS request with HTTP target → rejected (downgrade prevention)
    def test_https_request_rejects_http_target(self):
        req = self._get_request(secure=True)
        # http://testserver/ is rejected because require_https=True on secure request
        resp = safe_redirect(req, 'http://testserver/inbox/', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        # Location must not be the supplied http:// URL
        self.assertNotEqual(self._location(resp), 'http://testserver/inbox/')

    # Subdomain-spoofing: trusted.example.evil.example → rejected
    def test_trusted_substring_in_external_host_rejected(self):
        req = self._get_request()
        resp = safe_redirect(req, 'https://testserver.evil.example/', fallback='inbox')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.example', self._location(resp))


# ---------------------------------------------------------------------------
# Endpoint-level tests: delete_email
# ---------------------------------------------------------------------------

class DeleteEmailRedirectTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='del_redir', password='pass')
        self.client = Client(enforce_csrf_checks=False)
        self.client.force_login(self.user)

    def _make_email(self):
        return EmailMessage.objects.create(
            user=self.user, sender_email='a@b.com', subject='t', folder='inbox'
        )

    def _post(self, email_id, referer=None):
        url = reverse('delete_email', args=[email_id])
        extra = {'HTTP_REFERER': referer} if referer else {}
        return self.client.post(url, follow=False, **extra)

    # Operation still succeeds
    def test_delete_moves_to_trash(self):
        e = self._make_email()
        self._post(e.id)
        e.refresh_from_db()
        self.assertTrue(e.in_trash)

    def test_trash_email_is_permanently_deleted(self):
        e = self._make_email()
        e.in_trash = True
        e.save()
        self._post(e.id)
        self.assertFalse(EmailMessage.objects.filter(id=e.id).exists())

    # Redirect behavior
    def test_missing_referer_falls_back_to_inbox(self):
        e = self._make_email()
        resp = self._post(e.id, referer=None)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', resp['Location'])

    def test_internal_relative_referer_accepted(self):
        e = self._make_email()
        resp = self._post(e.id, referer='/inbox/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], '/inbox/')

    def test_same_host_absolute_referer_accepted(self):
        e = self._make_email()
        resp = self._post(e.id, referer='http://testserver/inbox/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], 'http://testserver/inbox/')

    def test_external_https_referer_rejected(self):
        e = self._make_email()
        resp = self._post(e.id, referer='https://attacker.example.invalid/steal')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('attacker.example.invalid', resp['Location'])
        self.assertIn('/inbox/', resp['Location'])

    def test_external_http_referer_rejected(self):
        e = self._make_email()
        resp = self._post(e.id, referer='http://evil.net/page')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.net', resp['Location'])

    def test_protocol_relative_external_referer_rejected(self):
        e = self._make_email()
        resp = self._post(e.id, referer='//evil.net/page')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.net', resp['Location'])

    def test_malformed_referer_falls_back(self):
        e = self._make_email()
        # This exercises the exception-guard path in safe_redirect
        resp = self._post(e.id, referer=':::not-a-url:::')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', resp['Location'])


# ---------------------------------------------------------------------------
# Endpoint-level tests: toggle_star
# ---------------------------------------------------------------------------

class ToggleStarRedirectTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='star_redir', password='pass')
        self.client = Client(enforce_csrf_checks=False)
        self.client.force_login(self.user)
        self.email = EmailMessage.objects.create(
            user=self.user, sender_email='x@y.com', subject='star', folder='inbox', starred=False
        )

    def _post(self, referer=None):
        url = reverse('toggle_star', args=[self.email.id])
        extra = {'HTTP_REFERER': referer} if referer else {}
        return self.client.post(url, follow=False, **extra)

    # Operation still succeeds
    def test_star_toggled(self):
        self._post()
        self.email.refresh_from_db()
        self.assertTrue(self.email.starred)

    # Redirect behavior
    def test_missing_referer_falls_back_to_inbox(self):
        resp = self._post(referer=None)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', resp['Location'])

    def test_internal_relative_referer_accepted(self):
        resp = self._post(referer='/inbox/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], '/inbox/')

    def test_same_host_absolute_referer_accepted(self):
        resp = self._post(referer='http://testserver/inbox/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], 'http://testserver/inbox/')

    def test_external_https_referer_rejected(self):
        resp = self._post(referer='https://attacker.example.invalid/steal')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('attacker.example.invalid', resp['Location'])
        self.assertIn('/inbox/', resp['Location'])

    def test_external_http_referer_rejected(self):
        resp = self._post(referer='http://evil.net/page')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.net', resp['Location'])

    def test_protocol_relative_external_referer_rejected(self):
        resp = self._post(referer='//evil.net/page')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.net', resp['Location'])

    def test_malformed_referer_falls_back(self):
        resp = self._post(referer=':::bad:::')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', resp['Location'])


# ---------------------------------------------------------------------------
# Endpoint-level tests: inbox bulk action
# ---------------------------------------------------------------------------

class InboxBulkActionRedirectTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='bulk_redir', password='pass')
        self.client = Client(enforce_csrf_checks=False)
        self.client.force_login(self.user)
        self.email = EmailMessage.objects.create(
            user=self.user, sender_email='b@c.com', subject='bulk', folder='inbox', unread=True
        )

    def _post(self, referer=None):
        url = reverse('inbox')
        extra = {'HTTP_REFERER': referer} if referer else {}
        return self.client.post(
            url,
            data={'action': 'mark_read', 'email_ids': [self.email.id]},
            follow=False,
            **extra
        )

    # Operation still works
    def test_bulk_mark_read_works(self):
        self._post()
        self.email.refresh_from_db()
        self.assertFalse(self.email.unread)

    # Redirect behavior
    def test_missing_referer_falls_back_to_inbox(self):
        resp = self._post(referer=None)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', resp['Location'])

    def test_internal_relative_referer_accepted(self):
        resp = self._post(referer='/inbox/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], '/inbox/')

    def test_same_host_absolute_referer_accepted(self):
        resp = self._post(referer='http://testserver/inbox/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], 'http://testserver/inbox/')

    def test_external_https_referer_rejected(self):
        resp = self._post(referer='https://attacker.example.invalid/steal')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('attacker.example.invalid', resp['Location'])
        self.assertIn('/inbox/', resp['Location'])

    def test_external_http_referer_rejected(self):
        resp = self._post(referer='http://evil.net/page')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.net', resp['Location'])

    def test_protocol_relative_external_referer_rejected(self):
        resp = self._post(referer='//evil.net/page')
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('evil.net', resp['Location'])

    def test_malformed_referer_falls_back(self):
        resp = self._post(referer=':::bad:::')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/inbox/', resp['Location'])
