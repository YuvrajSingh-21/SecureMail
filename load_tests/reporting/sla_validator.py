"""
SLA Validation Engine for SecureMail load testing.
Evaluates Locust environment statistics against target SLAs.
"""

from typing import Dict, Any, Tuple
from ..config import config


def validate_slas(environment: Any) -> Tuple[bool, Dict[str, Any]]:
    """
    Evaluates in-flight or finalized Locust environment stats against SLA targets.
    Returns (is_passed, results_dict).
    """
    stats = environment.stats.total
    num_requests = stats.num_requests
    num_failures = stats.num_failures

    if num_requests == 0:
        return False, {"error": "No requests executed"}

    error_rate = (num_failures / num_requests) * 100.0
    p95_latency = stats.get_response_time_percentile(0.95) or 0.0
    p99_latency = stats.get_response_time_percentile(0.99) or 0.0
    actual_rps = stats.total_rps

    checks = {
        "p95_latency_ms": {
            "actual": round(p95_latency, 2),
            "target": config.SLA.MAX_P95_LATENCY_MS,
            "passed": p95_latency <= config.SLA.MAX_P95_LATENCY_MS,
        },
        "p99_latency_ms": {
            "actual": round(p99_latency, 2),
            "target": config.SLA.MAX_P99_LATENCY_MS,
            "passed": p99_latency <= config.SLA.MAX_P99_LATENCY_MS,
        },
        "error_rate_percent": {
            "actual": round(error_rate, 4),
            "target": config.SLA.MAX_ERROR_RATE_PERCENT,
            "passed": error_rate <= config.SLA.MAX_ERROR_RATE_PERCENT,
        },
    }

    all_passed = all(c["passed"] for c in checks.values())

    summary = {
        "passed": all_passed,
        "total_requests": num_requests,
        "total_failures": num_failures,
        "throughput_rps": round(actual_rps, 2),
        "avg_latency_ms": round(stats.avg_response_time, 2),
        "median_latency_ms": round(stats.median_response_time, 2),
        "sla_checks": checks,
    }

    return all_passed, summary
