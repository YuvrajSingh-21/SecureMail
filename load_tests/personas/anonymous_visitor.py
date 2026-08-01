"""
Anonymous Visitor Persona for Public Pages Load Testing.
Simulates unauthenticated prospective users navigating public SaaS portals.
Configured with natural think-time and realistic page distribution.
"""

from locust import HttpUser, task, tag, between
from ..config import config
from ..public.public_pages import (
    get_landing_page,
    get_about_page,
    get_contact_page,
    get_privacy_page,
    get_terms_page,
    get_cookie_page,
    get_support_page,
)


class AnonymousVisitor(HttpUser):
    """
    Simulates unauthenticated visitors browsing public routes.
    Employs natural human think-time without hardcoded sleep delays.
    """
    min_wait, max_wait = config.THINK_TIMES.get("anonymous", (2.5, 5.5))
    wait_time = between(min_wait, max_wait)

    @tag("public", "landing")
    @task(10)
    def view_landing(self):
        """GET /"""
        get_landing_page(self.client)

    @tag("public", "about")
    @task(6)
    def view_about(self):
        """GET /about/"""
        get_about_page(self.client)

    @tag("public", "support")
    @task(6)
    def view_support(self):
        """GET /support/"""
        get_support_page(self.client)

    @tag("public", "privacy")
    @task(4)
    def view_privacy(self):
        """GET /privacy/"""
        get_privacy_page(self.client)

    @tag("public", "terms")
    @task(4)
    def view_terms(self):
        """GET /terms/"""
        get_terms_page(self.client)

    @tag("public", "cookie")
    @task(4)
    def view_cookie(self):
        """GET /cookie/"""
        get_cookie_page(self.client)

    @tag("public", "contact")
    @task(1)
    def view_contact(self):
        """GET /contact/"""
        get_contact_page(self.client)
