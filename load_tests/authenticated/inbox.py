"""
Authenticated Inbox workload for SecureMail load testing.
Discovers email IDs dynamically from rendered inbox HTML.
"""

import re
from typing import Any, List
from ..utils.http_client import safe_get


def get_inbox(client: Any) -> List[int]:
    """
    GET /inbox/ (Main Mailbox)
    Extracts and returns valid email IDs discovered in the HTML table/cards.
    """
    resp = safe_get(client, "/inbox/", name="[Auth] GET /inbox/", expected_status=200)
    discovered_ids: List[int] = []

    if resp and getattr(resp, "status_code", 0) == 200:
        html = getattr(resp, "text", "")
        # Match href="/email/123/" or href='/email/123/'
        matches = re.findall(r'href=[\'"]/email/(\d+)/[\'"]', html)
        if matches:
            discovered_ids = [int(m) for m in set(matches)]

    return discovered_ids
