"""
Centralized Configuration & SLA Definitions for SecureMail Performance Testing.
Handles environment variables, network timeouts, SLAs, user pools, and path definitions.
"""

import os
from typing import List, Dict, Any
from pathlib import Path

# Optional .env loading
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class SLAConfig:
    """Service Level Agreement targets for performance validation."""
    MAX_P95_LATENCY_MS: float = float(os.getenv("SLA_MAX_P95_LATENCY_MS", "350.0"))
    MAX_P99_LATENCY_MS: float = float(os.getenv("SLA_MAX_P99_LATENCY_MS", "800.0"))
    MAX_ERROR_RATE_PERCENT: float = float(os.getenv("SLA_MAX_ERROR_RATE_PERCENT", "0.10"))
    MIN_RPS: float = float(os.getenv("SLA_MIN_RPS", "10.0"))


class LoadTestConfig:
    """Enterprise-grade configuration module for load testing suite."""

    # Project Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    REPORTS_DIR: Path = BASE_DIR / "reports"
    LOGS_DIR: Path = BASE_DIR / "logs"

    # Target Host Routing
    BASE_URL: str = os.getenv(
        "LOCUST_HOST",
        os.getenv("SECUREMAIL_BASE_URL", "http://127.0.0.1:8000")
    ).rstrip("/")

    # Network / HTTP Settings
    REQUEST_TIMEOUT: float = float(os.getenv("LOCUST_TIMEOUT", "20.0"))
    KEEP_ALIVE: bool = os.getenv("LOCUST_KEEP_ALIVE", "true").lower() in ("true", "1", "yes")

    # Logging Settings
    LOG_LEVEL: str = os.getenv("LOCUST_LOG_LEVEL", "INFO").upper()

    # SLA Config
    SLA = SLAConfig()

    # Pre-authenticated OAuth Session Configuration
    SESSION_ID: str = os.getenv("SECUREMAIL_SESSION_ID", "").strip()
    SESSION_IDS: List[str] = [
        s.strip() for s in os.getenv("SECUREMAIL_SESSION_IDS", "").split(",") if s.strip()
    ]

    # Pre-configured OAuth User Pool (for local test runner session resolution)
    USER_POOL: List[str] = [
        u.strip() for u in os.getenv(
            "SECUREMAIL_USER_POOL",
            "singhisking210222,LoneWolf21,_stress_user_0,_stress_user_1,_stress_user_2,_stress_user_3,_stress_user_4,_stress_user_5,_stress_user_6,_stress_user_7,_stress_user_8,_stress_user_9,testaudit,security_tester"
        ).split(",") if u.strip()
    ]

    # Public Routes (to be benchmarked in Phase 2)
    PUBLIC_ROUTES: List[str] = [
        "/",
        "/about/",
        "/contact/",
        "/privacy/",
        "/terms/",
        "/cookie/",
        "/support/",
        "/login/",
    ]

    # Mailbox Folders
    FOLDERS: List[str] = [
        "inbox",
        "starred",
        "archive",
        "spam",
        "trash",
        "important",
        "suspicious",
        "malicious",
    ]

    # Search Terms for Realistic Query Simulation
    SEARCH_TERMS: List[str] = [
        "invoice",
        "security",
        "urgent",
        "verify",
        "account",
        "paypal",
        "meeting",
        "password",
        "update",
        "alert",
        "billing",
        "statement",
        "payment",
        "action",
    ]

    # Persona Think-Time Bounds (Min, Max in seconds)
    THINK_TIMES: Dict[str, tuple[float, float]] = {
        "anonymous": (float(os.getenv("THINK_ANON_MIN", "2.0")), float(os.getenv("THINK_ANON_MAX", "5.0"))),
        "normal_employee": (float(os.getenv("THINK_NORMAL_MIN", "2.5")), float(os.getenv("THINK_NORMAL_MAX", "6.0"))),
        "power_user": (float(os.getenv("THINK_POWER_MIN", "1.5")), float(os.getenv("THINK_POWER_MAX", "3.5"))),
        "soc_analyst": (float(os.getenv("THINK_SOC_MIN", "1.0")), float(os.getenv("THINK_SOC_MAX", "2.5"))),
        "compliance_officer": (float(os.getenv("THINK_COMPLIANCE_MIN", "3.0")), float(os.getenv("THINK_COMPLIANCE_MAX", "8.0"))),
    }

    @classmethod
    def ensure_directories(cls) -> None:
        """Ensures that artifacts, reports, and logs directories exist."""
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)


# Instantiate global singleton
config = LoadTestConfig()
config.ensure_directories()
