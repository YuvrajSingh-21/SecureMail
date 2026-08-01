"""
Authenticated Settings workload for SecureMail load testing.
"""

from typing import Any
from ..utils.http_client import safe_get


def get_settings(client: Any) -> Any:
    """GET /settings/ (Connected Account Status & Settings)"""
    return safe_get(client, "/settings/", name="[Auth] GET /settings/", expected_status=200)
