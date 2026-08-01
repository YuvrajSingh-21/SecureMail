"""Authenticated user workloads subpackage."""
from .dashboard import get_dashboard
from .inbox import get_inbox
from .profile import get_profile
from .reports import get_reports
from .settings import get_settings
from .email_detail import get_email_detail
from .folders import (
    get_folder,
    get_starred_folder,
    get_archive_folder,
    get_trash_folder,
    get_important_folder,
    get_suspicious_folder,
    get_malicious_folder,
    get_spam_folder,
    SUPPORTED_FOLDERS,
)
from .pagination import get_inbox_page

__all__ = [
    "get_dashboard",
    "get_inbox",
    "get_profile",
    "get_reports",
    "get_settings",
    "get_email_detail",
    "get_folder",
    "get_starred_folder",
    "get_archive_folder",
    "get_trash_folder",
    "get_important_folder",
    "get_suspicious_folder",
    "get_malicious_folder",
    "get_spam_folder",
    "SUPPORTED_FOLDERS",
    "get_inbox_page",
]
