"""
SecureMail Master Locust Entrypoint - Phase 8: Production Endurance (Soak) Test.
Executes sustained 30-minute endurance soak testing with 50 concurrent users:
- 40% Inbox Browsing
- 20% Email Detail Forensics
- 10% Search
- 10% Attachment Preview
- 5% Attachment Download
- 5% PDF Export
- 5% Gemini Explanation
- 5% Reports
Zero external Google OAuth calls. Pre-authenticated session reuse only.
"""

from locust import events
from load_tests.config import config
from load_tests.personas.mixed_heavy_user import MixedHeavyUser
from load_tests.utils.logging_config import setup_load_test_logger
from load_tests.reporting.json_exporter import export_json_summary
from load_tests.reporting.sla_validator import validate_slas

logger = setup_load_test_logger("locust_soak_test")

# Expose Phase 8 persona
__all__ = ["MixedHeavyUser"]


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    logger.info("=" * 80)
    logger.info("SecureMail Load Test: Phase 8 - Production Endurance (Soak) Test Initialized")
    logger.info(f"Target Host: {environment.host or config.BASE_URL}")
    logger.info(f"SLA Target P95 Latency: <= {config.SLA.MAX_P95_LATENCY_MS} ms")
    logger.info(f"SLA Target Max Error Rate: <= {config.SLA.MAX_ERROR_RATE_PERCENT}%")
    logger.info("=" * 80)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    logger.info("=" * 80)
    logger.info("SecureMail Load Test: Phase 8 - Production Endurance (Soak) Test Completed")

    passed, summary = validate_slas(environment)
    json_path = export_json_summary(environment, output_filename="phase8_summary.json")

    logger.info(f"Total Requests: {summary.get('total_requests', 0)}")
    logger.info(f"Total Failures: {summary.get('total_failures', 0)}")
    logger.info(f"Throughput: {summary.get('throughput_rps', 0.0)} req/s")
    logger.info(f"Average Latency: {summary.get('avg_latency_ms', 0.0)} ms")
    logger.info(f"Median Latency: {summary.get('median_latency_ms', 0.0)} ms")
    logger.info(f"SLA Passed: {passed} | Summary: {json_path}")
    logger.info("=" * 80)
