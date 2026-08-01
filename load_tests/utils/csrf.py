"""
CSRF extraction and token management for Django load testing.
"""

import re
from typing import Optional, Any


def extract_csrf_token(html_content: str) -> Optional[str]:
    """
    Extracts the CSRF middleware token from rendered HTML forms.
    Supports input tags with name='csrfmiddlewaretoken'.
    """
    if not html_content:
        return None

    match = re.search(
        r'<input[^>]+name=[\'"]csrfmiddlewaretoken[\'"][^>]+value=[\'"]([^\'"]+)[\'"]',
        html_content,
        re.IGNORECASE
    )
    if match:
        return match.group(1)

    # Fallback to alternate attribute ordering
    match_rev = re.search(
        r'<input[^>]+value=[\'"]([^\'"]+)[\'"][^>]+name=[\'"]csrfmiddlewaretoken[\'"]',
        html_content,
        re.IGNORECASE
    )
    if match_rev:
        return match_rev.group(1)

    return None


def get_client_csrf(client: Any) -> str:
    """Retrieves CSRF token from Locust client cookies if present."""
    if hasattr(client, "cookies"):
        return client.cookies.get("csrftoken", "")
    return ""
