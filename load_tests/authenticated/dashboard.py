"""
Authenticated Dashboard workload for SecureMail load testing.
"""

from typing import Any
from ..utils.http_client import safe_get


def get_dashboard(client: Any) -> Any:
    """GET /dashboard/ (SOC Overview & Threat Summary)"""
    return safe_get(client, "/dashboard/", name="[Auth] GET /dashboard/", expected_status=200)
