"""
Attachment Workload for SecureMail Load Testing.
Handles dynamic discovery, preview, and download of real attachments.
Validates status codes and content lengths.
"""

import re
import logging
from typing import List, Optional, Any
from ..utils.http_client import safe_get

logger = logging.getLogger("load_tests.attachments")


def extract_attachment_ids(html_text: str) -> List[int]:
    """
    Extracts attachment IDs dynamically from email view HTML.
    Supports download links, preview buttons, and inline metadata.
    """
    if not html_text:
        return []
    
    # Match /attachment/<id>/download/ or /attachment/<id>/preview/
    matches = re.findall(r'/attachment/(\d+)/(?:download|preview)/', html_text)
    
    # Match openPreviewModal('<id>', ...)
    modal_matches = re.findall(r'openPreviewModal\([\'"](\d+)[\'"]', html_text)
    
    combined = set(matches + modal_matches)
    return [int(att_id) for att_id in combined]


def preview_attachment(client: Any, attachment_id: int) -> Optional[Any]:
    """
    GET /attachment/<id>/preview/
    Loads attachment preview. Handles both 200 OK (text/pdf/image) and 302 redirects (unsupported types).
    """
    if not attachment_id:
        return None

    with client.get(
        f"/attachment/{attachment_id}/preview/",
        name="[Attachments] GET /attachment/[id]/preview/",
        catch_response=True,
        allow_redirects=False
    ) as resp:
        if resp.status_code in [200, 302]:
            resp.success()
            return resp
        else:
            resp.failure(f"Attachment preview failed: HTTP {resp.status_code}")
            return None


def download_attachment(client: Any, attachment_id: int) -> Optional[Any]:
    """
    GET /attachment/<id>/download/
    Downloads binary attachment and verifies response integrity.
    """
    if not attachment_id:
        return None

    with client.get(
        f"/attachment/{attachment_id}/download/",
        name="[Attachments] GET /attachment/[id]/download/",
        catch_response=True,
        allow_redirects=False
    ) as resp:
        if resp.status_code == 200:
            content_length = len(resp.content) if resp.content else 0
            if content_length > 0:
                resp.success()
                return resp
            else:
                resp.failure("Downloaded attachment was empty (0 bytes)")
                return None
        elif resp.status_code == 302:
            # Redirected gracefully
            resp.success()
            return resp
        else:
            resp.failure(f"Attachment download failed: HTTP {resp.status_code}")
            return None
