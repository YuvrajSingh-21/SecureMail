import os
import re

TEMPLATE_DIR = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"

FILES_TO_UPDATE = [
    "index.html",
    "login.html",
    "public_about.html",
    "public_contact.html",
    "public_privacy.html",
    "public_terms.html",
    "public_disclosure.html",
    "public_cookie.html",
    "public_support.html"
]

for filename in FILES_TO_UPDATE:
    path = os.path.join(TEMPLATE_DIR, filename)
    with open(path, "r") as f:
        content = f.read()
    
    # Change extends base.html to extends public_base.html
    content = re.sub(r'{%\s*extends\s+"base.html"\s*%}', '{% extends "public_base.html" %}', content)
    
    # Change block content to block public_content
    content = re.sub(r'{%\s*block\s+content\s*%}', '{% block public_content %}', content)
    content = re.sub(r'{%\s*endblock\s+content\s*%}', '{% endblock public_content %}', content) # just in case
    
    if filename == "index.html":
        # Remove the <div class="w-full min-h-full" style="..."> wrapper
        content = re.sub(r'<div class="w-full min-h-full" style="background: linear-gradient\(135deg, #0a0e1a 0%, #1e3a5f 50%, #0a0e1a 100%\);">', '', content)
        # Remove the <nav> block
        content = re.sub(r'<!-- Navigation -->.*?</nav>', '', content, flags=re.DOTALL)
        # Remove the footer include
        content = re.sub(r'{%\s*include\s+"components/footer.html"\s*%}', '', content)
        # Remove the closing </div> for the wrapper
        content = re.sub(r'\s*</div>\s*{%\s*endblock\s*%}', '\n{% endblock %}', content)
    
    if filename == "login.html":
        # Remove the <div class="w-full min-h-full... "> wrapper and background
        content = re.sub(r'<div class="w-full min-h-full[^"]*" style="background: linear-gradient[^"]*;">', '', content)
        content = re.sub(r'\s*</div>\s*{%\s*endblock\s*%}', '\n{% endblock %}', content)

    # Some templates might not have closing block tags explicitly named, just {% endblock %}
    
    with open(path, "w") as f:
        f.write(content)

print("Refactoring complete.")
