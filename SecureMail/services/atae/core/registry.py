import threading
from typing import Dict, List, Type, Optional
from dataclasses import dataclass
from .interfaces import BaseAnalyzer

@dataclass
class AnalyzerRegistration:
    analyzer_cls: Type[BaseAnalyzer]
    name: str
    mimes: List[str]
    magics: List[str]
    extensions: List[str]
    priority: int
    is_fallback: bool = False

class AnalyzerRegistry:
    _registry: List[AnalyzerRegistration] = []
    _lock = threading.RLock()

    @classmethod
    def register(cls, analyzer_cls: Type[BaseAnalyzer], name: str, mimes: List[str] = None, 
                 magics: List[str] = None, extensions: List[str] = None, 
                 priority: int = 50, is_fallback: bool = False):
        with cls._lock:
            # Prevent duplicate registration by name
            for existing in cls._registry:
                if existing.name == name:
                    return
            cls._registry.append(AnalyzerRegistration(
                analyzer_cls=analyzer_cls,
                name=name,
                mimes=mimes or [],
                magics=magics or [],
                extensions=extensions or [],
                priority=priority,
                is_fallback=is_fallback
            ))
            # Sort by priority descending
            cls._registry.sort(key=lambda x: x.priority, reverse=True)

    @classmethod
    def get_all(cls) -> List[AnalyzerRegistration]:
        with cls._lock:
            return list(cls._registry)

    @classmethod
    def clear(cls):
        with cls._lock:
            cls._registry.clear()
