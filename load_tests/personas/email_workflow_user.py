"""
Email Workflow User Persona for Phase 4 Load Testing.
Simulates realistic human email management patterns:
- Navigation Journeys (Dashboard -> Inbox -> Detail -> Search -> Detail -> Reports -> Profile -> Inbox)
- Folder Navigation (Inbox, Starred, Archive, Trash, Important, Suspicious, Malicious, Spam)
- Search Variations (Sender, Subject, Keyword, Empty, Invalid)
- Pagination (Pages 1, 2, 3)
- Read / Unread Revisit Behaviors
Zero hardcoded IDs, zero Google OAuth calls.
"""

import random
from typing import List
from locust import task, tag, between
from ..config import config
from .base_auth import BaseAuthenticatedUser
from ..authenticated.dashboard import get_dashboard
from ..authenticated.inbox import get_inbox
from ..authenticated.profile import get_profile
from ..authenticated.reports import get_reports
from ..authenticated.settings import get_settings
from ..authenticated.email_detail import get_email_detail
from ..authenticated.folders import get_folder, SUPPORTED_FOLDERS
from ..authenticated.pagination import get_inbox_page
from ..search.search_workload import (
    search_by_sender,
    search_by_subject,
    search_by_keyword,
    search_empty,
    search_invalid,
    SEARCH_SENDER_TERMS,
    SEARCH_SUBJECT_TERMS,
    SEARCH_KEYWORD_TERMS,
)


class EmailWorkflowUser(BaseAuthenticatedUser):
    """
    Simulates realistic enterprise user operating across the full email lifecycle.
    """
    min_wait, max_wait = config.THINK_TIMES.get("email_workflow", (2.0, 5.0))
    wait_time = between(min_wait, max_wait)

    def on_start(self):
        super().on_start()
        self.recent_opened_emails: List[int] = []

    def _track_opened(self, email_id: int):
        if email_id and email_id not in self.recent_opened_emails:
            self.recent_opened_emails.append(email_id)
            if len(self.recent_opened_emails) > 10:
                self.recent_opened_emails.pop(0)

    @tag("workflow", "full_journey")
    @task(6)
    def navigation_journey(self):
        """
        Sequential user journey:
        Dashboard -> Inbox -> Open Email -> Back to Inbox -> Search -> Open Result -> Reports -> Profile -> Inbox
        """
        # 1. Dashboard
        get_dashboard(self.client)

        # 2. Inbox
        new_ids = get_inbox(self.client)
        if new_ids:
            self.discovered_email_ids = list(set(self.discovered_email_ids + new_ids))

        # 3. Open Random Email
        email_id = self.get_random_email_id()
        if email_id:
            get_email_detail(self.client, email_id)
            self._track_opened(email_id)

        # 4. Back to Inbox
        get_inbox(self.client)

        # 5. Search
        query = random.choice(SEARCH_SUBJECT_TERMS + SEARCH_KEYWORD_TERMS)
        search_ids = search_by_keyword(self.client, query=query)

        # 6. Open Search Result (if found)
        if search_ids:
            target_id = random.choice(search_ids)
            get_email_detail(self.client, target_id)
            self._track_opened(target_id)

        # 7. Reports
        get_reports(self.client)

        # 8. Profile
        get_profile(self.client)

        # 9. Return to Inbox
        get_inbox(self.client)

    @tag("folders")
    @task(4)
    def folder_navigation(self):
        """
        Navigates across various mailbox folders:
        starred, archive, trash, important, suspicious, malicious, spam
        """
        folder = random.choice(SUPPORTED_FOLDERS)
        folder_ids = get_folder(self.client, folder)
        if folder_ids:
            self.discovered_email_ids = list(set(self.discovered_email_ids + folder_ids))
            # 30% chance to inspect an email from the folder
            if random.random() < 0.3:
                target_id = random.choice(folder_ids)
                get_email_detail(self.client, target_id)
                self._track_opened(target_id)

    @tag("search")
    @task(4)
    def search_workflows(self):
        """
        Exercises various search permutations:
        Sender, Subject, Keyword, Empty, Invalid
        """
        search_type = random.choice(["sender", "subject", "keyword", "empty", "invalid"])
        discovered: List[int] = []

        if search_type == "sender":
            term = random.choice(SEARCH_SENDER_TERMS)
            discovered = search_by_sender(self.client, query=term)
        elif search_type == "subject":
            term = random.choice(SEARCH_SUBJECT_TERMS)
            discovered = search_by_subject(self.client, query=term)
        elif search_type == "keyword":
            term = random.choice(SEARCH_KEYWORD_TERMS)
            discovered = search_by_keyword(self.client, query=term)
        elif search_type == "empty":
            discovered = search_empty(self.client)
        elif search_type == "invalid":
            discovered = search_invalid(self.client)

        if discovered:
            self.discovered_email_ids = list(set(self.discovered_email_ids + discovered))
            # Open discovered email
            if random.random() < 0.5:
                target_id = random.choice(discovered)
                get_email_detail(self.client, target_id)
                self._track_opened(target_id)

    @tag("pagination")
    @task(3)
    def pagination_workflow(self):
        """
        Traverses pages 1, 2, and 3 in the mailbox.
        """
        page_num = random.choice([1, 2, 3])
        if page_num == 1:
            page_ids = get_inbox(self.client)
        else:
            page_ids = get_inbox_page(self.client, page_num=page_num)

        if page_ids:
            self.discovered_email_ids = list(set(self.discovered_email_ids + page_ids))

    @tag("revisit")
    @task(4)
    def read_unread_revisit(self):
        """
        Simulates opening an email, returning to inbox, and revisiting recent emails.
        """
        # 1. Open a new random email
        email_id = self.get_random_email_id()
        if email_id:
            get_email_detail(self.client, email_id)
            self._track_opened(email_id)

        # 2. Revisit previously opened email if available
        if self.recent_opened_emails and random.random() < 0.6:
            revisit_id = random.choice(self.recent_opened_emails)
            get_email_detail(self.client, revisit_id)
