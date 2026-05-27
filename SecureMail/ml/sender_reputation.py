import logging
from ..models import SenderReputationModel

logger = logging.getLogger(__name__)

class SenderReputationEngine:
    def __init__(self):
        # Known highly trusted domains
        self.whitelist = ['google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com']
        
    def get_reputation(self, domain):
        if not domain:
            return 50.0
            
        domain = domain.lower()
        
        # Check whitelist
        if domain in self.whitelist:
            return 95.0
            
        try:
            record, created = SenderReputationModel.objects.get_or_create(
                domain=domain,
                defaults={'reputation_score': 50.0}
            )
            return record.reputation_score
        except Exception as e:
            logger.error(f"Error retrieving sender reputation for {domain}: {str(e)}")
            return 50.0

    def update_reputation(self, domain, is_phishing):
        if not domain or domain in self.whitelist:
            return
            
        domain = domain.lower()
        try:
            record, _ = SenderReputationModel.objects.get_or_create(
                domain=domain,
                defaults={'reputation_score': 50.0}
            )
            
            record.frequency += 1
            if is_phishing:
                record.historical_phishing_count += 1
            else:
                record.historical_safe_count += 1
                
            # Recalculate score (more conservative approach)
            total = record.historical_safe_count + record.historical_phishing_count
            if total > 0:
                safe_ratio = record.historical_safe_count / total
                # Slower confidence curve: requires 25 emails for full impact
                confidence = min(1.0, total / 25.0)
                
                # Base is 50. High confidence Safe pulls it to 100. High confidence Phish pulls it to 0.
                if safe_ratio > 0.5:
                    # Positive rep gain
                    record.reputation_score = 50.0 + (safe_ratio - 0.5) * 100.0 * confidence
                else:
                    # Negative rep loss
                    record.reputation_score = 50.0 - (0.5 - safe_ratio) * 100.0 * confidence
                
                record.reputation_score = min(100.0, max(0.0, record.reputation_score))
                
            record.save()
        except Exception as e:
            logger.error(f"Error updating sender reputation for {domain}: {str(e)}")
