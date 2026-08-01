"""
Inbox and Folder browsing task definitions with dynamic email discovery.
"""

import random
from typing import List, Any

from .config import config
from .common import safe_get, extract_email_ids


def get_inbox(client: Any) -> List[int]:
    """
    Renders the default Inbox view and dynamically discovers visible email IDs.
    """
    resp = safe_get(
        client,
        "/inbox/",
        name="[Inbox] GET /inbox/",
        expected_status=200
    )
    if resp and resp.text:
        return extract_email_ids(resp.text)
    return []


def get_folder(client: Any, folder: str = None) -> List[int]:
    """
    Browses a specific validated folder (e.g., starred, archive, spam, trash).
    """
    target_folder = folder or random.choice(config.FOLDERS)
    resp = safe_get(
        client,
        f"/inbox/{target_folder}/",
        name=f"[Inbox] GET /inbox/{target_folder}/",
        expected_status=200
    )
    if resp and resp.text:
        return extract_email_ids(resp.text)
    return []


def get_inbox_paginated(client: Any, page: int = 2) -> None:
    """
    Requests a paginated subset of the user's inbox.
    """
    safe_get(
        client,
        f"/inbox/?page={page}",
        name="[Inbox] GET /inbox/?page=[N]",
        expected_status=200
    )


def get_inbox_sorted_by_risk(client: Any) -> None:
    """
    Requests the inbox sorted descending by ML risk score.
    """
    safe_get(
        client,
        "/inbox/?sort=risk",
        name="[Inbox] GET /inbox/?sort=risk",
        expected_status=200
    )


def get_api_emails(client: Any) -> List[int]:
    """
    Queries the JSON email list endpoint and extracts all discovered email IDs.
    """
    resp = safe_get(
        client,
        "/api/emails/",
        name="[API] GET /api/emails/",
        headers={"Accept": "application/json"},
        expected_status=200
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if isinstance(data, list):
                return [item["id"] for item in data if isinstance(item, dict) and "id" in item]
        except Exception:
            pass
    return []
