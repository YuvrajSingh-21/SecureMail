import math
from collections import Counter
from ..core.context import AnalysisContext
from ..core.logger import get_atae_logger

logger = get_atae_logger("entropy")

class EntropyEngine:
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = Counter(data)
        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def compute_profile(self, data: bytes, profile_name: str = "whole_file") -> dict:
        """
        API designed to support multiple entropy profiles.
        Currently implements the base profile calculation.
        """
        return {
            "name": profile_name,
            "entropy": self.calculate_shannon_entropy(data)
        }

    def run(self, file_bytes: bytes, context: AnalysisContext, profile_name: str = "whole_file"):
        profile = self.compute_profile(file_bytes, profile_name)
        
        if "entropy_profile" not in context.metadata:
            context.metadata["entropy_profile"] = {}
            
        context.metadata["entropy_profile"][profile["name"]] = profile["entropy"]
        logger.debug(f"Computed {profile['name']} entropy: {profile['entropy']:.2f} for {context.analysis_id}")
        context.mark_stage_complete("entropy")
