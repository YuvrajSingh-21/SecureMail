"""
Logging configuration for SecureMail Load Testing Suite.
Provides structured logging to stdout and local log files.
"""

import sys
import logging
from pathlib import Path
from ..config import config


def setup_load_test_logger(name: str = "load_tests") -> logging.Logger:
    """Configures and returns a standardized logger for load test operations."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    if not logger.handlers:
        # Formatter
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Stream Handler (stdout)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        # File Handler
        try:
            log_file = config.LOGS_DIR / "load_test.log"
            file_handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            pass  # Fallback gracefully if filesystem write is restricted

    return logger
