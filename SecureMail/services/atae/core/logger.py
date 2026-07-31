import logging
from typing import Optional

def get_atae_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"atae.{name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - ATAE - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    return logger

class ContextualLogger(logging.LoggerAdapter):
    def __init__(self, logger: logging.Logger, analysis_id: str):
        super().__init__(logger, {"analysis_id": analysis_id})
        
    def process(self, msg, kwargs):
        return f"[Job: {self.extra['analysis_id']}] {msg}", kwargs

def get_contextual_logger(name: str, analysis_id: str) -> ContextualLogger:
    return ContextualLogger(get_atae_logger(name), analysis_id)
