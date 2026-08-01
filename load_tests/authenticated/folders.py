"""
Folder Navigation workloads for SecureMail load testing.
Navigates across inbox, starred, archive, trash, important, suspicious, malicious, and spam.
Dynamically extracts valid email IDs from each folder.
"""

import re
from typing import List, Any
from ..utils.http_client import safe_get

SUPPORTED_FOLDERS = [
    "inbox",
    "starred",
    "archive",
    "trash",
    "important",
    "suspicious",
    "malicious",
    "spam",
]


def _extract_ids(resp: Any) -> List[int]:
    """Extracts email IDs from HTML response."""
    if not resp or getattr(resp, "status_code", 0) != 200:
        return []
    html = getattr(resp, "text", "")
    matches = re.findall(r'href=[\'"]/email/(\d+)/[\'"]', html)
    return [int(m) for m in set(matches)] if matches else []


def get_folder(client: Any, folder_name: str) -> List[int]:
    """
    GET /inbox/<folder>/
    Navigates to a specific folder and discovers email IDs within it.
    """
    if folder_name == "inbox":
        endpoint = "/inbox/"
        request_name = "[Folders] GET /inbox/"
    else:
        endpoint = f"/inbox/{folder_name}/"
        request_name = f"[Folders] GET /inbox/{folder_name}/"

    resp = safe_get(client, endpoint, name=request_name, expected_status=200)
    return _extract_ids(resp)


def get_starred_folder(client: Any) -> List[int]:
    return get_folder(client, "starred")


def get_archive_folder(client: Any) -> List[int]:
    return get_folder(client, "archive")


def get_trash_folder(client: Any) -> List[int]:
    return get_folder(client, "trash")


def get_important_folder(client: Any) -> List[int]:
    return get_folder(client, "important")


def get_suspicious_folder(client: Any) -> List[int]:
    return get_folder(client, "suspicious")


def get_malicious_folder(client: Any) -> List[int]:
    return get_folder(client, "malicious")


def get_spam_folder(client: Any) -> List[int]:
    return get_folder(client, "spam")
