"""
Error classification and taxonomy for SecureMail load tests.
Classifies HTTP responses and network exceptions accurately.
"""

from enum import Enum
from typing import Optional, Any


class FailureType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"           # Redirected to /login/ or unauthenticated
    AUTHZ_FORBIDDEN = "AUTHZ_FORBIDDEN"     # HTTP 403 Forbidden
    RATE_LIMITED = "RATE_LIMITED"           # HTTP 429 Too Many Requests
    NOT_FOUND = "NOT_FOUND"                 # HTTP 404 Not Found
    SERVER_ERROR = "SERVER_ERROR"           # HTTP 500/502/503
    TIMEOUT = "TIMEOUT"                     # HTTP 504 / 408 or connection timeout
    APPLICATION_ERROR = "APPLICATION_ERROR" # Corrupted response or unhandled status


def classify_response(response: Any, expected_status: int = 200) -> Optional[FailureType]:
    """
    Evaluates response status and URL to determine failure taxonomy.
    Returns None if response is healthy and matches expected behavior.
    """
    status = getattr(response, "status_code", 0)
    url = getattr(response, "url", "") or ""
    req_path = getattr(response, "request_path", "") or ""

    # Check for unauthorized redirect to login
    if "/login/" in url and "login" not in req_path:
        return FailureType.AUTH_FAILURE

    if status == 401:
        return FailureType.AUTH_FAILURE
    elif status == 403:
        return FailureType.AUTHZ_FORBIDDEN
    elif status == 429:
        return FailureType.RATE_LIMITED
    elif status == 404:
        return FailureType.NOT_FOUND
    elif status in (500, 502, 503):
        return FailureType.SERVER_ERROR
    elif status in (504, 408):
        return FailureType.TIMEOUT
    elif status != expected_status and status >= 400:
        return FailureType.APPLICATION_ERROR

    return None
