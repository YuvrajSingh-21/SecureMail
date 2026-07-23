import re

with open('SecureMail/templates/components/sidebar.html', 'r') as f:
    content = f.read()

# Fix the incorrect titles
replacements = {
    'starred': 'Starred',
    'important': 'Important',
    'sent': 'Sent',
    'drafts': 'Drafts',
    'spam': 'Spam',
    'trash': 'Trash',
    'dashboard': 'Overview',
    'reports': 'Analytics',
    'settings': 'Settings',
    'about': 'About',
    'contact': 'Contact Us'
}

for nav, title in replacements.items():
    content = re.sub(
        rf'(data-nav="{nav}"\s*title=)"Inbox"',
        rf'\1"{title}"',
        content
    )

with open('SecureMail/templates/components/sidebar.html', 'w') as f:
    f.write(content)
