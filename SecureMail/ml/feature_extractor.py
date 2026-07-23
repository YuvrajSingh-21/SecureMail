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
    CTA_PHRASES = ['apply now', 'login', 'claim offer', 'set up alerts', 'verify account', 'click here', 'get started', 'sign up', 'access now', 'view details']
    
    # Neutral/Marketing keywords (should demote phishing probability)
    MARKETING_WORDS = ['internship', 'apply now', 'registration', 'opportunity', 'newsletter', 'hiring', 'utm_source', 'utm_medium', 'click_id']

    def extract_features(self, subject, body, sender_email, sender_name, attachments=None, html_body=""):
        """
        Extracts comprehensive features across Sender, URL, Subject, Body, and Attachments.
        Returns features and the specific phrases that triggered hits.
        """
        from bs4 import BeautifulSoup
        
        features = {}
        body_lower = body.lower()
        subj_lower = subject.lower()
        
        triggered_phrases = {
            'urgency': [w for w in self.PHISHING_URGENCY if w in body_lower or w in subj_lower],
            'credentials': [w for w in self.PHISHING_CREDENTIALS if w in body_lower or w in subj_lower],
            'money': [w for w in self.PHISHING_MONEY if w in body_lower or w in subj_lower],
            'authority': [w for w in self.PHISHING_AUTHORITY if w in body_lower or w in subj_lower],
            'scarcity': [w for w in self.SCARCITY_TACTICS if w in body_lower],
            'cta': [w for w in self.CTA_PHRASES if w in body_lower]
        }

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

        # Link Mismatch & Homoglyph Detection using HTML body
        link_mismatch = 0
        homoglyph_detected = 0
        if html_body:
            soup = BeautifulSoup(html_body, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].lower()
                text = a_tag.get_text().strip().lower()
                
                # Check for homoglyphs (Cyrillic characters mixed with Latin)
                if re.search(r'[\u0400-\u04FF]', href):
                    homoglyph_detected = 1
                
                # Check if visible text looks like a URL but points elsewhere
                if ('http' in text or 'www.' in text) and 'http' in href:
                    try:
                        text_domain = urlparse(text if 'http' in text else 'http://' + text).netloc
                        href_domain = urlparse(href).netloc
                        # Strip subdomains for comparison
                        text_base = '.'.join(text_domain.split('.')[-2:])
                        href_base = '.'.join(href_domain.split('.')[-2:])
                        if text_base and href_base and text_base != href_base:
                            link_mismatch = 1
                    except Exception:
                        pass
        
        features['link_mismatch'] = link_mismatch
        features['homoglyph_detected'] = homoglyph_detected

        # --- Subject Features ---
        features['subject_len'] = len(subject)
        features['subj_urgency'] = len([w for w in triggered_phrases['urgency'] if w in subj_lower])
        features['subj_money'] = len([w for w in triggered_phrases['money'] if w in subj_lower])
        features['subj_security'] = len([w for w in triggered_phrases['credentials'] if w in subj_lower])

        # --- Body Features ---
        features['body_len'] = len(body)
        
        # HTML Ratio
        tags = len(re.findall(r'<[^>]+>', body))
        features['html_tag_count'] = tags
        
        features['body_urgency'] = len([w for w in triggered_phrases['urgency'] if w in body_lower])
        features['body_money'] = len([w for w in triggered_phrases['money'] if w in body_lower])
        features['body_security'] = len([w for w in triggered_phrases['credentials'] if w in body_lower])
        features['body_authority'] = len(triggered_phrases['authority'])
        features['scarcity_count'] = len(triggered_phrases['scarcity'])
        
        # CTA Detection (Button/Action text)
        features['cta_phrase_count'] = len(triggered_phrases['cta'])
        
        # Refined login request indicators: Requires a specific credential phrase AND a link
        features['login_request_indicator'] = 1 if (features['body_security'] > 0 and features['url_count'] > 0) else 0

        total_chars = len(body)
        upper_chars = sum(1 for c in body if c.isupper())
        features['upper_ratio'] = upper_chars / total_chars if total_chars > 0 else 0

        # Marketing counters (for calibration)
        features['marketing_count'] = sum(1 for w in self.MARKETING_WORDS if w in body_lower or w in subj_lower)

        # --- Attachment Features ---
        features['attachment_count'] = len(attachments) if attachments else 0
        features['exec_attachment_count'] = sum(1 for a in attachments if a.get('filename', '').lower().endswith(('.exe', '.bat', '.scr', '.vbs', '.msi'))) if attachments else 0
        features['archive_attachment_count'] = sum(1 for a in attachments if a.get('filename', '').lower().endswith(('.zip', '.rar', '.7z', '.tar'))) if attachments else 0

        # Unified text for TF-IDF
        features['combined_text'] = f"{subject} {body}"
        
        # Add triggered phrases to result
        features['triggered_phrases'] = triggered_phrases
        
        return features

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
