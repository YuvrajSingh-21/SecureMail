"""
REST API Emails workload for SecureMail load tests.
Discovers active email IDs dynamically without hardcoding.
"""

from typing import Any, List
from ..utils.http_client import safe_get


def get_api_emails(client: Any) -> List[int]:
    """
    GET /api/emails/ (Retrieves paginated email list)
    Returns a list of integer email IDs extracted from the JSON response.
    """
    resp = safe_get(client, "/api/emails/", name="[API] GET /api/emails/", expected_status=200)
    email_ids: List[int] = []

    if resp and getattr(resp, "status_code", 0) == 200:
        try:
            data = resp.json()
            # Support both standard list and DRF paginated {results: [...]}
            results = data.get("results", data) if isinstance(data, dict) else data
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict) and "id" in item:
                        email_ids.append(int(item["id"]))
        except Exception:
            pass

    return email_ids
