"""
Mailbox Pagination workload for SecureMail load testing.
Tests multi-page traversal (page 1, page 2, page 3) across mailbox folders.
"""

import re
from typing import List, Any
from ..utils.http_client import safe_get


def _extract_ids(resp: Any) -> List[int]:
    """Extracts email IDs from HTML response."""
    if not resp or getattr(resp, "status_code", 0) != 200:
        return []
    html = getattr(resp, "text", "")
    matches = re.findall(r'href=[\'"]/email/(\d+)/[\'"]', html)
    return [int(m) for m in set(matches)] if matches else []


def get_inbox_page(client: Any, page_num: int = 2) -> List[int]:
    """GET /inbox/?page=[num]"""
    resp = safe_get(
        client,
        f"/inbox/?page={page_num}",
        name="[Pagination] GET /inbox/?page=[num]",
        expected_status=200
    )
    return _extract_ids(resp)
