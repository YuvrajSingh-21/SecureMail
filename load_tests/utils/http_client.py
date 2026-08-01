"""
Standardized HTTP client wrapper for Locust load testing.
Wraps GET/POST operations with error taxonomy, latency recording, and headers.
"""

from typing import Optional, Dict, Any
from ..config import config
from .error_classifier import classify_response, FailureType
from .csrf import get_client_csrf


def safe_get(
    client: Any,
    url: str,
    name: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    expected_status: int = 200,
    allow_redirects: bool = True
) -> Any:
    """Executes a safe GET request with automated response classification."""
    req_name = name or f"GET {url}"
    req_headers = headers or {}

    with client.get(
        url,
        headers=req_headers,
        name=req_name,
        timeout=config.REQUEST_TIMEOUT,
        allow_redirects=allow_redirects,
        catch_response=True
    ) as response:
        failure = classify_response(response, expected_status=expected_status)
        if failure:
            response.failure(f"[{failure.value}] GET {url} failed with status {response.status_code}")
        else:
            response.success()
        return response


def safe_post(
    client: Any,
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
    name: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    expected_status: int = 200,
    allow_redirects: bool = True
) -> Any:
    """Executes a safe POST request with automated CSRF attachment and error classification."""
    req_name = name or f"POST {url}"
    req_headers = headers or {}

    csrf_token = get_client_csrf(client)
    if csrf_token:
        if "X-CSRFToken" not in req_headers:
            req_headers["X-CSRFToken"] = csrf_token
        if data is not None and "csrfmiddlewaretoken" not in data:
            data["csrfmiddlewaretoken"] = csrf_token

    with client.post(
        url,
        data=data,
        json=json,
        headers=req_headers,
        name=req_name,
        timeout=config.REQUEST_TIMEOUT,
        allow_redirects=allow_redirects,
        catch_response=True
    ) as response:
        failure = classify_response(response, expected_status=expected_status)
        if failure:
            response.failure(f"[{failure.value}] POST {url} failed with status {response.status_code}")
        else:
            response.success()
        return response
