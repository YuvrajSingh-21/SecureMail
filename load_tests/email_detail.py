"""
Email Detail and Forensic inspection task definitions with attachment extraction.
"""

from typing import List, Optional, Any

from .common import safe_get, extract_attachment_ids


def get_email_detail(client: Any, email_id: Optional[int]) -> List[int]:
    """
    Renders full email forensic analysis view for a valid discovered email ID.
    Extracts and returns any attachment IDs discovered on the page.
    """
    if not email_id:
        return []

    resp = safe_get(
        client,
        f"/email/{email_id}/",
        name="[Email] GET /email/[id]/",
        expected_status=200
    )
    if resp and resp.text:
        return extract_attachment_ids(resp.text)
    return []


def get_api_email_detail(client: Any, email_id: Optional[int]) -> None:
    """
    Fetches JSON representation of forensic analysis for a specific email.
    """
    if not email_id:
        return

    safe_get(
        client,
        f"/api/email/{email_id}/",
        name="[API] GET /api/email/[id]/",
        headers={"Accept": "application/json"},
        expected_status=200
    )
