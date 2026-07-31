import os
import shutil
import uuid
import stat
from ..core.config import config
from ..core.logger import get_atae_logger

logger = get_atae_logger("workspace")

class TemporaryWorkspaceManager:
    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or config.temp_workspace_base
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
            # Ensure only the app user has access
            os.chmod(self.base_dir, stat.S_IRWXU)

    def create_workspace(self, analysis_id: str) -> str:
        safe_id = "".join(c for c in analysis_id if c.isalnum() or c in ("-", "_"))
        if not safe_id:
            safe_id = str(uuid.uuid4())
            
        path = os.path.join(self.base_dir, safe_id)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, stat.S_IRWXU)
        logger.info(f"Created secure workspace at {path}")
        return path

    def secure_wipe(self, path: str):
        """
        Securely wipe the directory.
        For Phase 1, we overwrite files with zeros before deletion.
        """
        if not os.path.exists(path):
            return
        
        try:
            for root, dirs, files in os.walk(path):
                for f in files:
                    file_path = os.path.join(root, f)
                    try:
                        size = os.path.getsize(file_path)
                        with open(file_path, "wb") as fd:
                            fd.write(b'\x00' * size)
                    except Exception as e:
                        logger.warning(f"Could not wipe {file_path}: {e}")
            shutil.rmtree(path)
            logger.info(f"Securely wiped and removed workspace {path}")
        except Exception as e:
            logger.error(f"Failed to wipe workspace {path}: {e}")
