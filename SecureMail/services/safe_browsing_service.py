import os
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

class SafeBrowsingService:
    def __init__(self):
        self.api_key = getattr(settings, 'SAFE_BROWSING_API_KEY', os.getenv('SAFE_BROWSING_API_KEY'))
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.client_id = "securemail-ai"
        self.client_version = "1.0.0"

    def check_urls(self, urls):
        """
        Check a list of URLs against Google Safe Browsing.
        Returns a list of matches.
        """
        if not self.api_key:
            logger.warning("SAFE_BROWSING_API_KEY not configured.")
            return []

        if not urls:
            return []

        payload = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls]
            }
        }

        try:
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload
            )
            
            if response.status_code == 200:
                return response.json().get('matches', [])
            else:
                logger.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error calling Safe Browsing API: {str(e)}")
            return []

    def check_url(self, url):
        """Check a single URL. Returns formatted result."""
        matches = self.check_urls([url])
        if matches:
            match = matches[0]
            threat_type = match.get('threatType')
            # Map threat types to risk scores
            risk_score = 90 if threat_type in ["MALWARE", "SOCIAL_ENGINEERING"] else 50
            return {
                'url': url,
                'threat_type': threat_type,
                'confidence': 1.0, # Lookup API is high confidence
                'risk_score': risk_score,
                'is_malicious': True,
                'report': match
            }
        
        return {
            'url': url,
            'threat_type': 'SAFE',
            'confidence': 1.0,
            'risk_score': 0,
            'is_malicious': False,
            'report': None
        }
