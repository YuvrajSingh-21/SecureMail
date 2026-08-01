"""
Mixed Heavy Workload Persona for Phase 6 Benchmark.
Matches the exact requested production distribution:
- 40% Inbox browsing (GET /inbox/, folders, pagination)
- 20% Email Detail (GET /email/<id>/)
- 10% Search (GET /inbox/?q=[term])
- 10% Attachment Preview (GET /attachment/<id>/preview/)
- 5% Attachment Download (GET /attachment/<id>/download/)
- 5% PDF Export (GET /email/<id>/export-pdf/)
- 5% Gemini AI Explanation (POST /email/<id>/generate-explanation/)
- 5% Reports (GET /reports/)
"""

import random
from typing import List
from locust import task, tag, between
from ..config import config
from .base_auth import BaseAuthenticatedUser
from ..authenticated.inbox import get_inbox
from ..authenticated.email_detail import get_email_detail
from ..authenticated.folders import get_folder, SUPPORTED_FOLDERS
from ..authenticated.pagination import get_inbox_page
from ..attachments.attachment_workload import (
    extract_attachment_ids,
    preview_attachment,
    download_attachment,
)
from ..reports.report_workload import (
    get_reports_dashboard,
    export_pdf_report,
    generate_ai_explanation,
)
from ..search.search_workload import (
    search_by_keyword,
    search_by_sender,
    search_by_subject,
    SEARCH_KEYWORD_TERMS,
    SEARCH_SENDER_TERMS,
    SEARCH_SUBJECT_TERMS,
)


class MixedHeavyUser(BaseAuthenticatedUser):
    """
    Simulates real-world enterprise mixed workload under high concurrency.
    """
    min_wait, max_wait = config.THINK_TIMES.get("normal_employee", (1.0, 3.0))
    wait_time = between(min_wait, max_wait)

    def on_start(self):
        super().on_start()
        self.discovered_attachment_ids: List[int] = []

    def _harvest_attachments(self, email_id: int):
        resp = get_email_detail(self.client, email_id)
        if resp and resp.text:
            att_ids = extract_attachment_ids(resp.text)
            if att_ids:
                self.discovered_attachment_ids = list(set(self.discovered_attachment_ids + att_ids))

    # 1. 40% Inbox browsing
    @tag("inbox_browsing")
    @task(40)
    def inbox_browsing(self):
        choice = random.random()
        if choice < 0.6:
            # Standard inbox
            new_ids = get_inbox(self.client)
            if new_ids:
                self.discovered_email_ids = list(set(self.discovered_email_ids + new_ids))
        elif choice < 0.85:
            # Folder browsing
            folder = random.choice(SUPPORTED_FOLDERS)
            f_ids = get_folder(self.client, folder)
            if f_ids:
                self.discovered_email_ids = list(set(self.discovered_email_ids + f_ids))
        else:
            # Pagination
            page_num = random.choice([2, 3])
            p_ids = get_inbox_page(self.client, page_num=page_num)
            if p_ids:
                self.discovered_email_ids = list(set(self.discovered_email_ids + p_ids))

    # 2. 20% Email Detail
    @tag("email_detail")
    @task(20)
    def email_detail(self):
        email_id = self.get_random_email_id()
        if email_id:
            resp = get_email_detail(self.client, email_id)
            if resp and resp.text:
                att_ids = extract_attachment_ids(resp.text)
                if att_ids:
                    self.discovered_attachment_ids = list(set(self.discovered_attachment_ids + att_ids))

    # 3. 10% Search
    @tag("search")
    @task(10)
    def search_workload(self):
        stype = random.choice(["keyword", "sender", "subject"])
        if stype == "keyword":
            term = random.choice(SEARCH_KEYWORD_TERMS)
            res = search_by_keyword(self.client, query=term)
        elif stype == "sender":
            term = random.choice(SEARCH_SENDER_TERMS)
            res = search_by_sender(self.client, query=term)
        else:
            term = random.choice(SEARCH_SUBJECT_TERMS)
            res = search_by_subject(self.client, query=term)
        if res:
            self.discovered_email_ids = list(set(self.discovered_email_ids + res))

    # 4. 10% Attachment Preview
    @tag("attachment_preview")
    @task(10)
    def attachment_preview(self):
        if not self.discovered_attachment_ids:
            email_id = self.get_random_email_id()
            if email_id:
                self._harvest_attachments(email_id)
        if self.discovered_attachment_ids:
            att_id = random.choice(self.discovered_attachment_ids)
            preview_attachment(self.client, att_id)

    # 5. 5% Attachment Download
    @tag("attachment_download")
    @task(5)
    def attachment_download(self):
        if not self.discovered_attachment_ids:
            email_id = self.get_random_email_id()
            if email_id:
                self._harvest_attachments(email_id)
        if self.discovered_attachment_ids:
            att_id = random.choice(self.discovered_attachment_ids)
            download_attachment(self.client, att_id)

    # 6. 5% PDF Export
    @tag("pdf_export")
    @task(5)
    def pdf_export(self):
        email_id = self.get_random_email_id()
        if email_id:
            export_pdf_report(self.client, email_id)

    # 7. 5% Gemini Explanation
    @tag("gemini_explanation")
    @task(5)
    def gemini_explanation(self):
        email_id = self.get_random_email_id()
        if email_id:
            generate_ai_explanation(self.client, email_id)

    # 8. 5% Reports
    @tag("reports")
    @task(5)
    def reports(self):
        get_reports_dashboard(self.client)
