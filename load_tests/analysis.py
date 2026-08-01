"""
Forensic Report Export and Attachment task definitions.
Guarantees attachments are only requested when discovered, eliminating unnecessary 404s.
"""

import logging
from typing import Optional, Any

from .common import safe_get

logger = logging.getLogger(__name__)


def export_pdf_report(client: Any, email_id: Optional[int]) -> None:
    """
    Generates and streams a high-resolution DFIR Forensic Audit PDF report.
    Only requests export for valid, discovered email IDs.
    """
    if not email_id:
        return

    resp = safe_get(
        client,
        f"/email/{email_id}/export-pdf/",
        name="[Export] GET /email/[id]/export-pdf/",
        expected_status=200
    )
    if resp and resp.content:
        if not resp.content.startswith(b"%PDF-"):
            logger.debug(f"Export PDF on email {email_id} returned non-PDF stream.")


def preview_attachment(client: Any, attachment_id: Optional[int]) -> None:
    """
    Previews a sanitized attachment file (text/image/pdf).
    Only executed when an attachment ID was positively extracted.
    """
    if not attachment_id:
        return

    safe_get(
        client,
        f"/attachment/{attachment_id}/preview/",
        name="[Attachment] GET /attachment/[id]/preview/",
        expected_status=200
    )


def download_attachment(client: Any, attachment_id: Optional[int]) -> None:
    """
    Downloads an email attachment.
    Only executed when an attachment ID was positively extracted.
    """
    if not attachment_id:
        return

    safe_get(
        client,
        f"/attachment/{attachment_id}/download/",
        name="[Attachment] GET /attachment/[id]/download/",
        expected_status=200
    )
