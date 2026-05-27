from django.core.exceptions import ValidationError

def validate_secure_domain(email):
    """
    Example validator to ensure email domain is not in a blacklist.
    """
    forbidden_domains = ['malicious-sender.com', 'scam-mail.net']
    domain = email.split('@')[-1]
    if domain in forbidden_domains:
        raise ValidationError(f"Domain {domain} is blacklisted.")
