"""
Base Authenticated HttpUser for SecureMail Load Testing.
Manages pre-authenticated session lifecycle and dynamic email discovery.
Fails fast with StopUser() on session expiration without retrying login or invoking OAuth.
"""

import itertools
import random
import logging
from typing import List, Optional
from locust import HttpUser
from locust.exception import StopUser
from ..auth.session_broker import assign_authenticated_session
from ..api.api_emails import get_api_emails
from ..authenticated.inbox import get_inbox

logger = logging.getLogger("auth_base_user")
_USER_COUNTER = itertools.count()


class BaseAuthenticatedUser(HttpUser):
    """Abstract base user for authenticated personas."""
    abstract = True

    def on_start(self):
        self.user_index = next(_USER_COUNTER)
        self.discovered_email_ids: List[int] = []

        # 1. Attach pre-authenticated session
        authenticated = assign_authenticated_session(self.client, user_index=self.user_index)
        if not authenticated:
            logger.error(f"[User #{self.user_index}] Pre-authenticated session expired/rejected. Halting virtual user.")
            raise StopUser()

        # 2. Discover available email IDs dynamically (no hardcoded IDs)
        self._discover_emails()

    def _discover_emails(self):
        """Discovers existing email IDs via REST API or Inbox DOM."""
        api_ids = get_api_emails(self.client)
        if api_ids:
            self.discovered_email_ids = list(set(api_ids))
        else:
            inbox_ids = get_inbox(self.client)
            if inbox_ids:
                self.discovered_email_ids = list(set(inbox_ids))

    def get_random_email_id(self) -> Optional[int]:
        """Returns a discovered email ID or None if the inbox is empty."""
        if self.discovered_email_ids:
            return random.choice(self.discovered_email_ids)
        return None
