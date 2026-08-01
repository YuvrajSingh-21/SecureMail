"""
Authenticated Profile & Security Audit Log workload for SecureMail load testing.
"""

from typing import Any
from ..utils.http_client import safe_get


def get_profile(client: Any) -> Any:
    """GET /profile/ (Account Profile & Security Audit Trail)"""
    return safe_get(client, "/profile/", name="[Auth] GET /profile/", expected_status=200)
