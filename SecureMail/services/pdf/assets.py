import os
from pathlib import Path
from reportlab.platypus import Image

def get_logo_path_str():
    current_file = Path(__file__).resolve()
    base_dir = current_file.parent.parent.parent.parent
    possible_paths = [
        base_dir / "SecureMail" / "static" / "SecureMail" / "images" / "logo.png",
        base_dir / "static" / "logo.png",
        base_dir.parent / "logo.png"
    ]
    for path in possible_paths:
        if path.exists():
            return str(path)
    return None

def get_logo_image(width=35, height=40):
    path = get_logo_path_str()
    if path:
        return Image(path, width=width, height=height)
    return Image(None, width=width, height=height) if False else ""
