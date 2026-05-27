import os
import hashlib
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

class VirusTotalService:
    def __init__(self):
        self.api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', os.getenv('VIRUSTOTAL_API_KEY'))
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

    def get_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_hash(self, file_hash):
        """Check if a file hash is already known by VirusTotal."""
        if not self.api_key:
            logger.warning("VIRUSTOTAL_API_KEY not configured.")
            return None

        url = f"{self.base_url}/files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"Hash {file_hash} not found on VirusTotal.")
                return None
            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error calling VirusTotal API: {str(e)}")
            return None

    def scan_file(self, file_path):
        """Upload a file to VirusTotal for scanning."""
        if not self.api_key:
            return None

        url = f"{self.base_url}/files"
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = requests.post(url, headers=self.headers, files=files)
            
            if response.status_code == 200:
                return response.json() # Returns analysis ID
            else:
                logger.error(f"VirusTotal upload failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error uploading to VirusTotal: {str(e)}")
            return None

    def get_report(self, analysis_id):
        """Get the analysis report for a submitted file."""
        if not self.api_key:
            return None

        url = f"{self.base_url}/analyses/{analysis_id}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"VirusTotal report fetch failed: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error fetching VirusTotal report: {str(e)}")
            return None

    def is_malicious_report(self, report):
        """Helper to determine if a report indicates a malicious file."""
        if not report:
            return False
        
        # Check standard V3 file report structure
        if 'data' in report and 'attributes' in report['data']:
            stats = report['data']['attributes'].get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            return malicious_count > 0 or suspicious_count > 5
        
        # Check analysis report structure
        if 'data' in report and 'attributes' in report['data']:
            stats = report['data']['attributes'].get('stats', {})
            return stats.get('malicious', 0) > 0
            
        return False
