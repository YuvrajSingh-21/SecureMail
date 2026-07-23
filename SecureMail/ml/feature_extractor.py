import re
import pandas as pd
import math
from collections import Counter
from urllib.parse import urlparse

class FeatureExtractor:
    FREE_PROVIDERS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com']
    
    # Refined phishing keywords - requiring more specific technical patterns
    PHISHING_URGENCY = ['action required', 'account suspended', 'unauthorized access', 'immediate action', 'last chance', 'closing soon']
    PHISHING_CREDENTIALS = ['reset your password', 'security update', 'confirm identity', 'verify your account']
    PHISHING_MONEY = ['wire transfer', 'tax refund', 'overdue payment', 'inheritance from', 'reward', 'cash prize', 'exclusive bonus']
    PHISHING_AUTHORITY = ['official notice', 'department of', 'system administrator', 'security team', 'verified by']
    SCARCITY_TACTICS = ['limited time', 'while supplies last', 'only a few left', 'hurry', 'expiring']
    
    # Neutral/Marketing keywords (should demote phishing probability)
    MARKETING_WORDS = ['internship', 'apply now', 'registration', 'opportunity', 'newsletter', 'hiring', 'utm_source', 'utm_medium', 'click_id']

    def extract_features(self, subject, body, sender_email, sender_name, attachments=None):
        """
        Extracts comprehensive features across Sender, URL, Subject, Body, and Attachments.
        """
        features = {}
        
        # --- Sender Features ---
        domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ''
        features['sender_domain'] = domain
        features['is_free_provider'] = 1 if domain in self.FREE_PROVIDERS else 0
        features['domain_length'] = len(domain)
        features['domain_entropy'] = self._calculate_entropy(domain)
        
        # Display name mismatch (e.g. sender_name claims to be PayPal, but email is gmail.com)
        features['display_name_mismatch'] = 1 if (sender_name and domain not in sender_name.lower() and not features['is_free_provider']) else 0

        # --- URL Features ---
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        features['url_count'] = len(urls)
        features['ip_url_count'] = sum(1 for url in urls if self._is_ip_url(url))
        features['shortened_url_count'] = sum(1 for url in urls if self._is_short_url(url))
        features['suspicious_tld_count'] = sum(1 for url in urls if self._has_suspicious_tld(url))
        features['https_ratio'] = sum(1 for url in urls if url.startswith('https')) / len(urls) if urls else 1.0

        # --- Subject Features ---
        subj_lower = subject.lower()
        features['subject_len'] = len(subject)
        features['subj_urgency'] = sum(1 for w in self.PHISHING_URGENCY if w in subj_lower)
        features['subj_money'] = sum(1 for w in self.PHISHING_MONEY if w in subj_lower)
        features['subj_security'] = sum(1 for w in self.PHISHING_CREDENTIALS if w in subj_lower)

        # --- Body Features ---
        body_lower = body.lower()
        features['body_len'] = len(body)
        
        # HTML Ratio
        tags = len(re.findall(r'<[^>]+>', body))
        features['html_tag_count'] = tags
        
        features['body_urgency'] = sum(1 for w in self.PHISHING_URGENCY if w in body_lower)
        features['body_money'] = sum(1 for w in self.PHISHING_MONEY if w in body_lower)
        features['body_security'] = sum(1 for w in self.PHISHING_CREDENTIALS if w in body_lower)
        features['body_authority'] = sum(1 for w in self.PHISHING_AUTHORITY if w in body_lower)
        features['scarcity_count'] = sum(1 for w in self.SCARCITY_TACTICS if w in body_lower)
        
        # Refined login request indicators: Requires a specific credential phrase AND a link
        features['login_request_indicator'] = 1 if (features['body_security'] > 0 and features['url_count'] > 0) else 0

        total_chars = len(body)
        upper_chars = sum(1 for c in body if c.isupper())
        features['upper_ratio'] = upper_chars / total_chars if total_chars > 0 else 0

        # Marketing counters (for calibration)
        features['marketing_count'] = sum(1 for w in self.MARKETING_WORDS if w in body_lower or w in subj_lower)

        # --- Attachment Features ---
        features['attachment_count'] = len(attachments) if attachments else 0
        features['exec_attachment_count'] = sum(1 for a in attachments if a['filename'].lower().endswith(('.exe', '.bat', '.scr', '.vbs', '.msi'))) if attachments else 0
        features['archive_attachment_count'] = sum(1 for a in attachments if a['filename'].lower().endswith(('.zip', '.rar', '.7z', '.tar'))) if attachments else 0

        # Combined text for TF-IDF
        features['combined_text'] = f"{subject} {body}".lower()

        return features

    def _is_ip_url(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0]
            return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
        except:
            return False

    def _is_short_url(self, url):
        shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly']
        try:
            domain = urlparse(url).netloc.lower()
            return domain in shorteners
        except:
            return False

    def _has_suspicious_tld(self, url):
        suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.cn', '.cc', '.su', '.live', '.loan']
        try:
            domain = urlparse(url).netloc.lower()
            return any(domain.endswith(tld) for tld in suspicious_tlds)
        except:
            return False

    def _calculate_entropy(self, text):
        if not text:
            return 0
        counts = Counter(text)
        probs = [count / len(text) for count in counts.values()]
        return -sum(p * math.log(p, 2) for p in probs)

    def to_dataframe(self, feature_list):
        return pd.DataFrame(feature_list)
