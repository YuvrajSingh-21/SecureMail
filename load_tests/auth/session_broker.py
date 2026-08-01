"""
OAuth Session Broker for SecureMail Load Testing Suite.
Consumes pre-authenticated Django sessions supplied externally or via configured test accounts.
Zero interaction with Google OAuth, PKCE, or external authentication providers.
Fails fast with 'SessionExpired' if the session is invalid or revoked.
"""

import os
import random
import logging
from typing import Optional, List, Any
from locust.exception import StopUser
from ..config import config

logger = logging.getLogger("auth_session_broker")

_SESSION_CACHE: List[str] = []


def _get_or_load_sessions() -> List[str]:
    """Retrieves session IDs from environment or local test account store."""
    global _SESSION_CACHE
    if _SESSION_CACHE:
        return _SESSION_CACHE

    sessions: List[str] = []

    # 1. Ingest explicit environment sessions
    if config.SESSION_IDS:
        sessions.extend(config.SESSION_IDS)
    if config.SESSION_ID and config.SESSION_ID not in sessions:
        sessions.append(config.SESSION_ID)

    if sessions:
        _SESSION_CACHE = sessions
        logger.info(f"Loaded {len(sessions)} pre-authenticated session(s) from environment.")
        return _SESSION_CACHE

    # 2. Local test account fallback for CI/developer runs
    try:
        import django
        from django.conf import settings
        if not settings.configured:
            os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Email_Phisher.settings")
            django.setup()

        from django.contrib.auth.models import User
        from django.contrib.sessions.backends.db import SessionStore
        from django.contrib.auth import HASH_SESSION_KEY, SESSION_KEY, BACKEND_SESSION_KEY

        for username in config.USER_POOL:
            user = User.objects.filter(username=username).first()
            if not user:
                continue

            session = SessionStore()
            session[SESSION_KEY] = str(user.pk)
            session[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
            session[HASH_SESSION_KEY] = user.get_session_auth_hash()
            session.save()
            sessions.append(session.session_key)

        if sessions:
            _SESSION_CACHE = sessions
            logger.info(f"Provisioned {len(sessions)} pre-authenticated test user session(s).")
            return _SESSION_CACHE
    except Exception as exc:
        logger.warning(f"Could not load local test sessions: {exc}")

    return _SESSION_CACHE


def assign_authenticated_session(client: Any, user_index: Optional[int] = None) -> bool:
    """
    Attaches a pre-authenticated sessionid cookie to the Locust client and verifies health.
    If session is invalid or expired, reports 'SessionExpired' and returns False.
    """
    sessions = _get_or_load_sessions()
    if not sessions:
        logger.error("No pre-authenticated sessions available in pool.")
        return False

    session_key = sessions[user_index % len(sessions)] if user_index is not None else random.choice(sessions)

    # Attach session cookie
    if hasattr(client.cookies, "set"):
        client.cookies.set("sessionid", session_key)
    else:
        client.cookies["sessionid"] = session_key

    # Healthcheck verification GET /dashboard/
    with client.get(
        "/dashboard/",
        name="[Auth] Session Healthcheck",
        timeout=config.REQUEST_TIMEOUT,
        allow_redirects=True,
        catch_response=True
    ) as resp:
        if resp.status_code == 200 and "/login/" not in getattr(resp, "url", ""):
            resp.success()
            return True
        else:
            resp.failure(f"SessionExpired (HTTP {resp.status_code}, redirect: {getattr(resp, 'url', '')})")
            return False
