"""
OAuth Session Management & Provisioning for SecureMail Locust Load Tests.
Benchmarks SecureMail post-authentication without hitting external Google OAuth servers.
Supports:
1. Direct session IDs passed via environment variables (SECUREMAIL_SESSION_IDS / SECUREMAIL_SESSION_ID).
2. Automated local session store provisioning for configured OAuth test accounts.
"""

import os
import logging
import random
from typing import Optional, List, Any
from .config import config

logger = logging.getLogger(__name__)

# Global cache of active session keys
_SESSION_POOL_CACHE: List[str] = []


def _initialize_session_pool() -> List[str]:
    """
    Builds the pool of active, authenticated OAuth session IDs.
    Prioritizes explicit environment variable session keys; falls back to
    generating/reading active sessions for configured OAuth test users.
    """
    global _SESSION_POOL_CACHE
    if _SESSION_POOL_CACHE:
        return _SESSION_POOL_CACHE

    # 1. Check explicit session IDs from environment
    sessions: List[str] = []
    if config.SESSION_IDS:
        sessions.extend(config.SESSION_IDS)
    if config.SESSION_ID and config.SESSION_ID not in sessions:
        sessions.append(config.SESSION_ID)

    if sessions:
        _SESSION_POOL_CACHE = sessions
        logger.info(f"Loaded {len(sessions)} pre-authenticated OAuth session(s) from environment.")
        return _SESSION_POOL_CACHE

    # 2. Local test provisioning via Django SessionStore
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
            _SESSION_POOL_CACHE = sessions
            logger.info(f"Provisioned {len(sessions)} OAuth test user session(s) for local benchmarking.")
            return _SESSION_POOL_CACHE
    except Exception as exc:
        logger.warning(f"Could not provision local test user sessions: {exc}")

    return _SESSION_POOL_CACHE


def assign_oauth_session(client: Any, user_index: Optional[int] = None) -> bool:
    """
    Assigns an authenticated OAuth session cookie to the Locust virtual user.
    Verifies that the session is valid and accepted by SecureMail.
    """
    pool = _initialize_session_pool()
    if not pool:
        logger.error("No authenticated OAuth sessions available in pool. Provide SECUREMAIL_SESSION_IDS or configure test users.")
        return False

    if user_index is not None:
        session_key = pool[user_index % len(pool)]
    else:
        session_key = random.choice(pool)

    # Inject the sessionid cookie into Locust's HTTP client
    if hasattr(client.cookies, "set"):
        client.cookies.set("sessionid", session_key)
    else:
        client.cookies["sessionid"] = session_key

    # Step 1: Healthcheck request to verify session validity
    with client.get(
        "/dashboard/",
        name="[Auth] Verify OAuth Session",
        timeout=config.REQUEST_TIMEOUT,
        allow_redirects=True,
        catch_response=True
    ) as resp:
        if resp.status_code == 200 and "/login/" not in getattr(resp, "url", ""):
            resp.success()
            return True
        elif resp.status_code == 429:
            resp.failure(f"Verification rate-limited (HTTP 429)")
            return False
        else:
            resp.failure(f"OAuth session verification failed (HTTP {resp.status_code}, URL: {getattr(resp, 'url', '')})")
            return False


def logout_oauth_user(client: Any) -> None:
    """
    Gracefully executes logout on user exit (on_stop).
    """
    try:
        with client.get(
            "/logout/",
            name="[Auth] GET /logout/",
            timeout=config.REQUEST_TIMEOUT,
            allow_redirects=True,
            catch_response=True
        ) as resp:
            resp.success()
    except Exception as exc:
        logger.debug(f"Logout exception: {exc}")
    finally:
        client.cookies.clear()
