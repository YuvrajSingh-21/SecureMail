import os
import re

TEMPLATE_DIR = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"

def replace_in_file(path):
    with open(path, 'r') as f:
        content = f.read()

    original_content = content
    
    # Needs {% load static %} if we use {% static %}
    has_load_static = '{% load static %}' in content or '{% extends' in content

    if not '{% load static %}' in content and not '{% extends' in content:
        content = '{% load static %}\n' + content

    # 1. Navbar / Public Navbar / Footer / Sidebar icons (36px -> app-logo-sm)
    # <div class="..."> <i data-lucide="shield-check" ...></i> </div>
    content = re.sub(
        r'<div class="[^"]*w-10 h-10[^"]*">[\s]*<i data-lucide="shield-check"[^>]*></i>[\s]*</div>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-sm" alt="SecureMail">',
        content
    )
    content = re.sub(
        r'<div class="[^"]*w-8 h-8[^"]*">[\s]*<i data-lucide="shield-check"[^>]*></i>[\s]*</div>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-sm" alt="SecureMail">',
        content
    )
    
    # 2. Login SVG block -> 90px (app-logo-lg)
    # <div class="... w-16 h-16 ..."><i data-lucide="shield-check" ...></i></div> or the SVG block
    content = re.sub(
        r'<div class="[^"]*w-16 h-16[^"]*">[\s]*<i data-lucide="shield-check"[^>]*></i>[\s]*</div>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-lg" alt="SecureMail">',
        content
    )
    content = re.sub(
        r'<svg class="w-5 h-5"[^>]*>.*?</svg>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-lg" alt="SecureMail">',
        content, flags=re.DOTALL
    )

    # 3. Big shield in Loading screens or Empty states or email-view -> 64px or 120px
    content = re.sub(
        r'<svg class="w-7 h-7"[^>]*>.*?</svg>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-md" alt="SecureMail">',
        content, flags=re.DOTALL
    )
    content = re.sub(
        r'<svg class="w-6 h-6"[^>]*>.*?</svg>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-md" alt="SecureMail">',
        content, flags=re.DOTALL
    )

    # 4. Any direct lucide icons that are acting as main branding
    # index.html
    content = re.sub(
        r'<div class="w-12 h-12[^"]*">[\s]*<i data-lucide="shield-check"[^>]*></i>[\s]*</div>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-lg" alt="SecureMail">',
        content
    )
    content = re.sub(
        r'<i data-lucide="shield"[^>]*class="w-5 h-5 text-white"[^>]*></i>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-sm" alt="SecureMail">',
        content
    )
    content = re.sub(
        r'<i data-lucide="shield-check"[^>]*class="w-6 h-6 text-white"[^>]*></i>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-sm" alt="SecureMail">',
        content
    )
    content = re.sub(
        r'<i data-lucide="shield-check"[^>]*class="w-4 h-4 text-white"[^>]*></i>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-sm" alt="SecureMail">',
        content
    )
    
    # about.html huge shield -> app-logo-xl
    content = re.sub(
        r'<div class="w-20 h-20[^"]*">[\s]*<i data-lucide="shield-check"[^>]*></i>[\s]*</div>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-xl" alt="SecureMail">',
        content
    )
    
    # footer
    content = re.sub(
        r'<div class="w-8 h-8[^"]*">[\s]*<i data-lucide="shield-check"[^>]*></i>[\s]*</div>',
        r'<img src="{% static \'SecureMail/images/logo.png\' %}" class="app-logo app-logo-sm" alt="SecureMail">',
        content
    )
    
    if content != original_content:
        with open(path, 'w') as f:
            f.write(content)
        return True
    return False

modified = []
for root, _, files in os.walk(TEMPLATE_DIR):
    for f in files:
        if f.endswith('.html'):
            if replace_in_file(os.path.join(root, f)):
                modified.append(os.path.join(root, f))
                
print("Modified files:")
for m in modified:
    print(m)
