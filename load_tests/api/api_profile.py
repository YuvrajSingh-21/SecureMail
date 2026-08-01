"""
REST API Profile workload for SecureMail load tests.
"""

from typing import Any
from ..utils.http_client import safe_get


def get_api_profile(client: Any) -> Any:
    """GET /api/profile/ (Retrieves security metrics and threat counters)"""
    return safe_get(client, "/api/profile/", name="[API] GET /api/profile/", expected_status=200)
