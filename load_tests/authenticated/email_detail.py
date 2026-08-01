"""
Authenticated Email Detail workload for SecureMail load testing.
Inspects email detail forensics without hardcoding IDs or generating 404s.
"""

from typing import Any, Optional
from ..utils.http_client import safe_get


def get_email_detail(client: Any, email_id: Optional[int]) -> Any:
    """
    GET /email/<id>/ (Forensic Threat Analysis & Header Detail)
    Only executes if a valid email_id is provided. Zero artificial 404s.
    """
    if not email_id:
        return None

    return safe_get(
        client,
        f"/email/{email_id}/",
        name="[Auth] GET /email/[id]/",
        expected_status=200
    )
