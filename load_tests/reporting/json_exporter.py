"""
JSON Test Summary Exporter for CI/CD pipelines.
"""

import json
from pathlib import Path
from typing import Any, Dict
from ..config import config
from .sla_validator import validate_slas


def export_json_summary(environment: Any, output_filename: str = "summary.json") -> Path:
    """Exports structured test metrics and SLA evaluations to JSON."""
    passed, summary_data = validate_slas(environment)

    output_path = config.REPORTS_DIR / output_filename
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    return output_path
