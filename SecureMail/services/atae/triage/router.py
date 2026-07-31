from typing import Optional, Type, Dict
from ..core.registry import AnalyzerRegistry
from ..core.interfaces import BaseAnalyzer
from ..core.config import config

class AttachmentRouter:
    def __init__(self, routing_map: Optional[Dict[str, str]] = None):
        self.routing_map = routing_map or config.mime_routing

    def route(self, true_mime: str) -> Optional[Type[BaseAnalyzer]]:
        category = self.routing_map.get(true_mime, "generic")
        return AnalyzerRegistry.get_analyzer(category)
