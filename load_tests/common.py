"""
Common utilities, regex parsers, and safe HTTP wrappers for Locust load tests.
Ensures uniform request metrics naming, response validation, and connection reuse.
"""

import re
import logging
from typing import List, Optional, Any, Set
from bs4 import BeautifulSoup

from .config import config

logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for maximum parsing efficiency
CSRF_REGEX = re.compile(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']')
EMAIL_ID_REGEX = re.compile(r'/email/(\d+)/')
ATTACHMENT_ID_REGEX = re.compile(r'/attachment/(\d+)/(?:preview|download)/')


def extract_csrf_token(html_content: str) -> Optional[str]:
    """
    Extracts the Django CSRF token from rendered HTML markup.
    Uses fast regex first, falling back to BeautifulSoup if needed.
    """
    if not html_content:
        return None

    match = CSRF_REGEX.search(html_content)
    if match:
        return match.group(1)

    try:
        soup = BeautifulSoup(html_content, "html.parser")
        csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        if csrf_input and csrf_input.get("value"):
            return csrf_input["value"]
    except Exception as exc:
        logger.debug(f"BeautifulSoup CSRF extraction failed: {exc}")

    return None


def extract_email_ids(html_content: str) -> List[int]:
    """
    Parses valid email IDs from rendered HTML anchor links.
    Returns a deduplicated list of integer IDs found on the page.
    """
    if not html_content:
        return []

    raw_matches = EMAIL_ID_REGEX.findall(html_content)
    ids = []
    seen: Set[int] = set()
    for m in raw_matches:
        try:
            val = int(m)
            if val not in seen:
                seen.add(val)
                ids.append(val)
        except ValueError:
            continue

    return ids


def extract_attachment_ids(html_content: str) -> List[int]:
    """
    Parses attachment IDs from email detail HTML anchor links.
    Ensures tests only preview/download attachments that actually exist.
    """
    if not html_content:
        return []

    raw_matches = ATTACHMENT_ID_REGEX.findall(html_content)
    ids = []
    seen: Set[int] = set()
    for m in raw_matches:
        try:
            val = int(m)
            if val not in seen:
                seen.add(val)
                ids.append(val)
        except ValueError:
            continue

    return ids


def safe_get(
    client: Any,
    url: str,
    name: Optional[str] = None,
    headers: Optional[dict] = None,
    expected_status: int = 200,
    allow_redirects: bool = True
) -> Any:
    """
    Executes a GET request with proper error classification.
    Distinguishes between valid responses, redirects, auth failures, and server errors.
    """
    metric_name = name or url
    req_headers = headers or {}

    with client.get(
        url,
        name=metric_name,
        headers=req_headers,
        timeout=config.REQUEST_TIMEOUT,
        allow_redirects=allow_redirects,
        catch_response=True
    ) as response:
        # Check for unauthenticated redirect to login
        if "/login" in response.url and "/login" not in url:
            response.failure(f"Unauthenticated: Redirected to login on {metric_name}")
            return response

        # Expected Success
        if response.status_code == expected_status or (expected_status == 200 and response.status_code in (200, 302)):
            response.success()
            return response

        # Specific HTTP error classifications
        elif response.status_code == 401:
            response.failure(f"Unauthorized (401) on {metric_name}")
        elif response.status_code == 403:
            response.failure(f"Forbidden (403) on {metric_name}")
        elif response.status_code == 404:
            response.failure(f"Not Found (404) on {metric_name}")
        elif response.status_code == 429:
            response.failure(f"Rate Limited (429) on {metric_name}")
        elif response.status_code >= 500:
            response.failure(f"Server Error ({response.status_code}) on {metric_name}")
        else:
            response.failure(f"Unexpected status code {response.status_code} on {metric_name}")

        return response


def safe_post(
    client: Any,
    url: str,
    data: Optional[dict] = None,
    name: Optional[str] = None,
    headers: Optional[dict] = None,
    expected_status: int = 200,
    allow_redirects: bool = True
) -> Any:
    """
    Executes a POST request with CSRF headers, standard metrics grouping, and error handling.
    """
    metric_name = name or url
    req_headers = headers or {}
    post_data = data or {}

    # Auto-inject CSRF token header if cookie is present
    csrf_cookie = client.cookies.get("csrftoken")
    if csrf_cookie and "X-CSRFToken" not in req_headers:
        req_headers["X-CSRFToken"] = csrf_cookie

    with client.post(
        url,
        data=post_data,
        name=metric_name,
        headers=req_headers,
        timeout=config.REQUEST_TIMEOUT,
        allow_redirects=allow_redirects,
        catch_response=True
    ) as response:
        if response.status_code == expected_status or (expected_status == 200 and response.status_code in (200, 302)):
            response.success()
            return response
        elif response.status_code == 403:
            response.failure(f"Forbidden / CSRF Failure (403) on {metric_name}")
        elif response.status_code == 429:
            response.failure(f"Rate Limited (429) on {metric_name}")
        elif response.status_code >= 500:
            response.failure(f"Server Error ({response.status_code}) on {metric_name}")
        else:
            response.failure(f"Unexpected status code {response.status_code} on {metric_name}")

        return response
