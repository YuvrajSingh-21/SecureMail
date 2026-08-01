"""
Search and Filtering workloads for SecureMail Load Testing.
Implements sender, subject, keyword, empty, and invalid search patterns.
Dynamically extracts discovered email IDs without hardcoding.
"""

import re
import urllib.parse
from typing import List, Optional, Any
from ..utils.http_client import safe_get

SEARCH_SENDER_TERMS = ["google.com", "security", "alert", "service", "support", "admin"]
SEARCH_SUBJECT_TERMS = ["login", "account", "update", "verify", "password", "statement"]
SEARCH_KEYWORD_TERMS = ["urgent", "invoice", "payment", "access", "notice", "phish"]
SEARCH_INVALID_TERMS = ["__nonexistent_term_98765__", "qwertyuiopasdfghjkl_000", "invalid_token_999"]


def _extract_ids(resp: Any) -> List[int]:
    """Extracts email IDs from HTML response."""
    if not resp or getattr(resp, "status_code", 0) != 200:
        return []
    html = getattr(resp, "text", "")
    matches = re.findall(r'href=[\'"]/email/(\d+)/[\'"]', html)
    return [int(m) for m in set(matches)] if matches else []


def search_by_sender(client: Any, query: Optional[str] = None) -> List[int]:
    """GET /inbox/?q=[sender_term]"""
    term = query or "security"
    encoded = urllib.parse.quote(term)
    resp = safe_get(
        client,
        f"/inbox/?q={encoded}",
        name="[Search] GET /inbox/?q=[sender]",
        expected_status=200
    )
    return _extract_ids(resp)


def search_by_subject(client: Any, query: Optional[str] = None) -> List[int]:
    """GET /inbox/?q=[subject_term]"""
    term = query or "account"
    encoded = urllib.parse.quote(term)
    resp = safe_get(
        client,
        f"/inbox/?q={encoded}",
        name="[Search] GET /inbox/?q=[subject]",
        expected_status=200
    )
    return _extract_ids(resp)


def search_by_keyword(client: Any, query: Optional[str] = None) -> List[int]:
    """GET /inbox/?q=[keyword]"""
    term = query or "urgent"
    encoded = urllib.parse.quote(term)
    resp = safe_get(
        client,
        f"/inbox/?q={encoded}",
        name="[Search] GET /inbox/?q=[keyword]",
        expected_status=200
    )
    return _extract_ids(resp)


def search_empty(client: Any) -> List[int]:
    """GET /inbox/?q= (Empty Search)"""
    resp = safe_get(
        client,
        "/inbox/?q=",
        name="[Search] GET /inbox/?q=[empty]",
        expected_status=200
    )
    return _extract_ids(resp)


def search_invalid(client: Any) -> List[int]:
    """GET /inbox/?q=[invalid_term] (0 matches expected, 200 OK)"""
    term = SEARCH_INVALID_TERMS[0]
    encoded = urllib.parse.quote(term)
    resp = safe_get(
        client,
        f"/inbox/?q={encoded}",
        name="[Search] GET /inbox/?q=[invalid]",
        expected_status=200
    )
    return _extract_ids(resp)


def filter_by_read_status(client: Any, status: str = "unread") -> List[int]:
    """GET /inbox/?filter=[unread|read]"""
    resp = safe_get(
        client,
        f"/inbox/?filter={status}",
        name=f"[Search] GET /inbox/?filter={status}",
        expected_status=200
    )
    return _extract_ids(resp)
