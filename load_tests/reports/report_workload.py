"""
Reporting, PDF Export, and AI Explanation workloads for SecureMail Load Testing.
Handles:
- PDF Forensic Export (GET /email/<id>/export-pdf/)
- AI Threat Explanation (POST /email/<id>/generate-explanation/)
- SOC Executive Reports (GET /reports/)
"""

import time
import logging
from typing import Optional, Any
from ..utils.http_client import safe_get

logger = logging.getLogger("load_tests.reports")


def get_reports_dashboard(client: Any) -> Optional[Any]:
    """
    GET /reports/
    Loads executive reporting and threat analytics overview.
    """
    return safe_get(
        client,
        "/reports/",
        name="[Reports] GET /reports/",
        expected_status=200
    )


def export_pdf_report(client: Any, email_id: int) -> Optional[Any]:
    """
    GET /email/<id>/export-pdf/
    Measures ReportLab PDF compilation latency and validates PDF stream.
    """
    if not email_id:
        return None

    t0 = time.perf_counter()
    with client.get(
        f"/email/{email_id}/export-pdf/",
        name="[Reports] GET /email/[id]/export-pdf/",
        catch_response=True,
        allow_redirects=False
    ) as resp:
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0

        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            content_length = len(resp.content) if resp.content else 0
            if "pdf" in content_type.lower() or content_length > 100:
                resp.success()
                return resp
            else:
                resp.failure(f"PDF export returned invalid payload ({content_length} bytes)")
                return None
        elif resp.status_code == 302:
            resp.success()
            return resp
        else:
            resp.failure(f"PDF export failed: HTTP {resp.status_code}")
            return None


def generate_ai_explanation(client: Any, email_id: int) -> Optional[Any]:
    """
    POST /email/<id>/generate-explanation/
    Measures Gemini AI / cached forensic explanation generation.
    Passes CSRF token and AJAX headers.
    """
    if not email_id:
        return None

    # Retrieve CSRF token from session cookies
    csrf_token = client.cookies.get("csrftoken", "")
    headers = {
        "X-CSRFToken": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{client.base_url}/email/{email_id}/" if hasattr(client, 'base_url') else f"http://127.0.0.1:8000/email/{email_id}/"
    }

    t0 = time.perf_counter()
    with client.post(
        f"/email/{email_id}/generate-explanation/",
        headers=headers,
        name="[Reports] POST /email/[id]/generate-explanation/",
        catch_response=True
    ) as resp:
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0

        if resp.status_code == 200:
            try:
                data = resp.json()
                status = data.get("status")
                if status in ["generated", "cached"]:
                    resp.success()
                    return resp
                elif "explanation" in data:
                    resp.success()
                    return resp
                else:
                    resp.failure(f"Unexpected JSON response: {data}")
                    return None
            except Exception as e:
                resp.failure(f"Invalid JSON response: {str(e)}")
                return None
        elif resp.status_code == 404:
            # Email has no threat analysis attached
            resp.success()
            return resp
        else:
            resp.failure(f"AI explanation failed: HTTP {resp.status_code} - {resp.text[:100]}")
            return None
