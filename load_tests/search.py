"""
Search and Filtering task definitions for SecureMail Locust load testing.
"""

import random
from typing import List, Optional, Any

from .config import config
from .common import safe_get, extract_email_ids


def search_inbox(client: Any, query: Optional[str] = None) -> List[int]:
    """
    Executes a search query against email subjects and senders.
    Returns any matched email IDs.
    """
    search_term = query or random.choice(config.SEARCH_TERMS)
    resp = safe_get(
        client,
        f"/inbox/?q={search_term}",
        name="[Search] GET /inbox/?q=[term]",
        expected_status=200
    )
    if resp and resp.text:
        return extract_email_ids(resp.text)
    return []


def filter_unread_emails(client: Any) -> List[int]:
    """
    Filters inbox items by unread status.
    """
    resp = safe_get(
        client,
        "/inbox/?filter=unread",
        name="[Search] GET /inbox/?filter=unread",
        expected_status=200
    )
    if resp and resp.text:
        return extract_email_ids(resp.text)
    return []


def filter_read_emails(client: Any) -> List[int]:
    """
    Filters inbox items by read status.
    """
    resp = safe_get(
        client,
        "/inbox/?filter=read",
        name="[Search] GET /inbox/?filter=read",
        expected_status=200
    )
    if resp and resp.text:
        return extract_email_ids(resp.text)
    return []
