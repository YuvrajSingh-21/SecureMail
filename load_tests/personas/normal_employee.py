"""
Normal Employee Persona for Phase 3 Authenticated Workload.
Simulates standard daily enterprise operations across Dashboard, Inbox, Profile, Reports, Settings, and APIs.
"""

from locust import task, tag, between
from ..config import config
from .base_auth import BaseAuthenticatedUser
from ..authenticated.dashboard import get_dashboard
from ..authenticated.inbox import get_inbox
from ..authenticated.profile import get_profile
from ..authenticated.reports import get_reports
from ..authenticated.settings import get_settings
from ..authenticated.email_detail import get_email_detail
from ..api.api_profile import get_api_profile
from ..api.api_emails import get_api_emails


class NormalEmployee(BaseAuthenticatedUser):
    """
    Simulates regular enterprise employees operating within their authenticated mailbox.
    """
    min_wait, max_wait = config.THINK_TIMES.get("normal_employee", (2.5, 6.0))
    wait_time = between(min_wait, max_wait)

    @tag("dashboard")
    @task(5)
    def view_dashboard(self):
        """GET /dashboard/"""
        get_dashboard(self.client)

    @tag("inbox")
    @task(6)
    def browse_inbox(self):
        """GET /inbox/"""
        new_ids = get_inbox(self.client)
        if new_ids:
            self.discovered_email_ids = list(set(self.discovered_email_ids + new_ids))

    @tag("email_detail")
    @task(4)
    def inspect_email(self):
        """GET /email/<id>/"""
        email_id = self.get_random_email_id()
        if email_id:
            get_email_detail(self.client, email_id)

    @tag("profile")
    @task(2)
    def view_profile(self):
        """GET /profile/"""
        get_profile(self.client)

    @tag("reports")
    @task(2)
    def view_reports(self):
        """GET /reports/"""
        get_reports(self.client)

    @tag("settings")
    @task(1)
    def view_settings(self):
        """GET /settings/"""
        get_settings(self.client)

    @tag("api", "profile")
    @task(2)
    def poll_api_profile(self):
        """GET /api/profile/"""
        get_api_profile(self.client)

    @tag("api", "emails")
    @task(3)
    def poll_api_emails(self):
        """GET /api/emails/"""
        new_ids = get_api_emails(self.client)
        if new_ids:
            self.discovered_email_ids = list(set(self.discovered_email_ids + new_ids))
