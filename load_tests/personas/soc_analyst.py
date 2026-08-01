"""
SOC Analyst Persona for Phase 5 Attachment & Report Workflows.
Simulates realistic cybersecurity analysts performing:
- Deep forensic email inspection
- Attachment discovery, preview, and download
- PDF technical forensic report export
- AI threat explanation generation
- Executive security reports analytics
"""

import random
from typing import List
from locust import task, tag, between
from ..config import config
from .base_auth import BaseAuthenticatedUser
from ..authenticated.inbox import get_inbox
from ..authenticated.email_detail import get_email_detail
from ..authenticated.folders import get_malicious_folder, get_suspicious_folder
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


class SOCAnalystUser(BaseAuthenticatedUser):
    """
    Simulates SOC Analyst inspecting threat emails, analyzing attachments, and exporting reports.
    """
    min_wait, max_wait = config.THINK_TIMES.get("soc_analyst", (2.0, 5.0))
    wait_time = between(min_wait, max_wait)

    def on_start(self):
        super().on_start()
        self.discovered_attachment_ids: List[int] = []

    def _inspect_email_and_harvest(self, email_id: int) -> str:
        """Opens email detail, extracts and stores dynamic attachment IDs."""
        resp = get_email_detail(self.client, email_id)
        if resp and resp.text:
            att_ids = extract_attachment_ids(resp.text)
            if att_ids:
                self.discovered_attachment_ids = list(set(self.discovered_attachment_ids + att_ids))
            return resp.text
        return ""

    @tag("forensics", "email_inspection")
    @task(5)
    def forensic_email_inspection(self):
        """
        SOC analyst reviews high-risk emails, checks forensic signals, and harvests attachments.
        """
        # Alternate between threat folder, suspicious folder, and standard inbox
        pool_choice = random.choice(["threats", "suspicious", "inbox"])
        if pool_choice == "threats":
            folder_ids = get_malicious_folder(self.client)
        elif pool_choice == "suspicious":
            folder_ids = get_suspicious_folder(self.client)
        else:
            folder_ids = get_inbox(self.client)

        if folder_ids:
            self.discovered_email_ids = list(set(self.discovered_email_ids + folder_ids))
            target_id = random.choice(folder_ids)
            self._inspect_email_and_harvest(target_id)
        elif self.discovered_email_ids:
            target_id = self.get_random_email_id()
            if target_id:
                self._inspect_email_and_harvest(target_id)

    @tag("attachments", "preview_download")
    @task(4)
    def attachment_lifecycle(self):
        """
        Executes attachment preview and download on dynamically discovered attachments.
        """
        # If no attachments discovered yet, inspect a random email to harvest
        if not self.discovered_attachment_ids:
            email_id = self.get_random_email_id()
            if email_id:
                self._inspect_email_and_harvest(email_id)

        if self.discovered_attachment_ids:
            target_att_id = random.choice(self.discovered_attachment_ids)
            
            # 1. Preview Attachment
            preview_attachment(self.client, target_att_id)
            
            # 2. Download Attachment (50% probability after preview)
            if random.random() < 0.5:
                download_attachment(self.client, target_att_id)

    @tag("pdf_export")
    @task(3)
    def pdf_report_export(self):
        """
        Triggers ReportLab PDF generation for a dynamically selected email.
        """
        email_id = self.get_random_email_id()
        if email_id:
            export_pdf_report(self.client, email_id)

    @tag("ai_explanation")
    @task(3)
    def ai_threat_explanation(self):
        """
        Requests Gemini AI / cached forensic explanation for analyzed email.
        """
        email_id = self.get_random_email_id()
        if email_id:
            generate_ai_explanation(self.client, email_id)

    @tag("executive_reports")
    @task(2)
    def executive_reports_review(self):
        """
        Reviews aggregate SOC security statistics and top phishing domains.
        """
        get_reports_dashboard(self.client)
