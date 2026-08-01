"""
Public Pages workload implementation for SecureMail load testing.
Tests only unauthenticated public routes with zero authentication logic.
"""

from typing import Any
from ..utils.http_client import safe_get


def get_landing_page(client: Any) -> Any:
    """GET / (Landing / Homepage)"""
    return safe_get(client, "/", name="[Public] GET /", expected_status=200)


def get_about_page(client: Any) -> Any:
    """GET /about/ (About & Threat Statistics)"""
    return safe_get(client, "/about/", name="[Public] GET /about/", expected_status=200)


def get_contact_page(client: Any) -> Any:
    """GET /contact/ (Contact & Support Form View)"""
    return safe_get(client, "/contact/", name="[Public] GET /contact/", expected_status=200)


def get_privacy_page(client: Any) -> Any:
    """GET /privacy/ (Privacy Policy)"""
    return safe_get(client, "/privacy/", name="[Public] GET /privacy/", expected_status=200)


def get_terms_page(client: Any) -> Any:
    """GET /terms/ (Terms of Service)"""
    return safe_get(client, "/terms/", name="[Public] GET /terms/", expected_status=200)


def get_cookie_page(client: Any) -> Any:
    """GET /cookie/ (Cookie Policy)"""
    return safe_get(client, "/cookie/", name="[Public] GET /cookie/", expected_status=200)


def get_support_page(client: Any) -> Any:
    """GET /support/ (Help Center & FAQ)"""
    return safe_get(client, "/support/", name="[Public] GET /support/", expected_status=200)
