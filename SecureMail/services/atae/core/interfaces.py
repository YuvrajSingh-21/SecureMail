from abc import ABC, abstractmethod
from typing import List
from .context import AnalysisContext
from .models import Finding

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, file_bytes: bytes, context: AnalysisContext) -> List[Finding]:
        """
        Statically analyze file bytes and return a list of findings.
        The context is provided to attach deeper artifacts (e.g., extracted IOCs)
        and track limits.
        """
        pass
