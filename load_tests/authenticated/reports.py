"""
Authenticated Reports workload for SecureMail load testing.
"""

from typing import Any
from ..utils.http_client import safe_get


def get_reports(client: Any) -> Any:
    """GET /reports/ (Threat Intelligence & Forensic Analytics)"""
    return safe_get(client, "/reports/", name="[Auth] GET /reports/", expected_status=200)
