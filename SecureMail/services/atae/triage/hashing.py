import hashlib
from typing import Dict

class HashingService:
    @staticmethod
    def compute_hashes(file_bytes: bytes) -> Dict[str, str]:
        """
        Compute MD5, SHA1, and SHA256 hashes for the given bytes.
        """
        return {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }
