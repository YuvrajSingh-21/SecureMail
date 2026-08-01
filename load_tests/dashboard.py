"""
Dashboard, Reports, and Profile task definitions for SecureMail Locust load testing.
"""

from typing import Any
from .common import safe_get


def get_dashboard(client: Any) -> None:
    """
    Renders the authenticated SOC overview dashboard.
    """
    safe_get(
        client,
        "/dashboard/",
        name="[Dashboard] GET /dashboard/",
        expected_status=200
    )


def get_reports(client: Any) -> None:
    """
    Renders aggregated security reports (threat distribution, top sender domains).
    """
    safe_get(
        client,
        "/reports/",
        name="[Reports] GET /reports/",
        expected_status=200
    )


def get_profile(client: Any) -> None:
    """
    Renders user profile and recent security audit trail.
    """
    safe_get(
        client,
        "/profile/",
        name="[Profile] GET /profile/",
        expected_status=200
    )


def get_settings(client: Any) -> None:
    """
    Renders user security preferences and notification settings.
    """
    safe_get(
        client,
        "/settings/",
        name="[Settings] GET /settings/",
        expected_status=200
    )


def get_api_profile(client: Any) -> None:
    """
    Fetches JSON security score and profile metadata via REST API.
    """
    safe_get(
        client,
        "/api/profile/",
        name="[API] GET /api/profile/",
        headers={"Accept": "application/json"},
        expected_status=200
    )
