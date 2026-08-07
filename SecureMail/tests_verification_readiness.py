from django.test import TestCase, Client
from django.urls import reverse

class GoogleOAuthVerificationReadinessTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_public_pages_accessible_anonymously(self):
        public_urls = [
            ('/', 'Securamail — Intelligent Email Security'),
            ('/about/', 'About Us — Securamail'),
            ('/privacy/', 'Privacy Policy — Securamail'),
            ('/terms/', 'Terms of Service — Securamail'),
            ('/contact/', 'Contact Support — Securamail'),
            ('/support/', 'Help & Support — Securamail'),
            ('/cookie/', 'Cookie Policy — Securamail'),
            ('/login/', 'Authenticate — Securamail'),
            ('/robots.txt', None),
            ('/sitemap.xml', None),
        ]
        for url, expected_title in public_urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, f"URL {url} failed with status {response.status_code}")
            if expected_title:
                self.assertContains(response, expected_title, html=False)

    def test_home_page_purpose_and_metadata(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Verify app name & domain & canonical
        self.assertIn('Securamail', content)
        self.assertIn('<link rel="canonical" href="https://securamail.me/">', content)
        self.assertIn('<meta property="og:site_name" content="Securamail">', content)
        
        # Verify clear explanation of purpose
        self.assertIn('AI-powered email security platform', content)
        self.assertIn('connect their Gmail account', content)
        self.assertIn('analyze email content for phishing', content)
        self.assertIn('identify potentially dangerous emails and attachments', content)

    def test_privacy_policy_compliance_content(self):
        response = self.client.get('/privacy/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        # Check domain & developer email & brand
        self.assertIn('Securamail', content)
        self.assertIn('https://securamail.me/', content)
        self.assertIn('team.asteroids.2024@gmail.com', content)
        
        # Check Google API Services User Data Policy & Limited Use
        self.assertIn('Google API Services User Data Policy', content)
        self.assertIn('Limited Use', content)
        
        # Check explicit data commitments
        self.assertIn('NO DATA SELLING', content)
        self.assertIn('NO PUBLIC AI TRAINING', content)
        self.assertIn('NO ADVERTISING', content)
        self.assertIn('AES-256 encryption at rest', content)
        self.assertIn('https://myaccount.google.com/permissions', content)

    def test_terms_of_service_compliance_content(self):
        response = self.client.get('/terms/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        
        self.assertIn('Securamail', content)
        self.assertIn('https://securamail.me/', content)
        self.assertIn('team.asteroids.2024@gmail.com', content)
        self.assertIn('Google OAuth', content)
        self.assertIn('Limitation of Liability', content)

    def test_robots_and_sitemap(self):
        robots_res = self.client.get('/robots.txt')
        self.assertEqual(robots_res.status_code, 200)
        self.assertIn('Sitemap: https://securamail.me/sitemap.xml', robots_res.content.decode('utf-8'))
        
        sitemap_res = self.client.get('/sitemap.xml')
        self.assertEqual(sitemap_res.status_code, 200)
        self.assertIn('https://securamail.me/', sitemap_res.content.decode('utf-8'))
        self.assertIn('https://securamail.me/privacy/', sitemap_res.content.decode('utf-8'))
        self.assertIn('https://securamail.me/terms/', sitemap_res.content.decode('utf-8'))
