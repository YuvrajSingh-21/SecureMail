import logging

logger = logging.getLogger(__name__)

class RiskEngine:
    """
    Combines analysis from multiple sources to calculate a final 0-100 risk score.
    REFACTORED: Aligned with 40/70 production thresholds.
    """
    
    # Weightings for different factors
    WEIGHTS = {
        'content': 0.40,      # Local ML linguistic analysis
        'links': 0.30,        # Safe Browsing URL analysis
        'attachments': 0.20,  # VirusTotal malware analysis
        'reputation': 0.10    # Sender domain reputation
    }

    def calculate_risk(self, gemini_result=None, link_results=None, attachment_results=None, sender_email=""):
        """
        Main entry point for risk calculation.
        """
        factors = {}
        
        # 1. Content Risk (Local ML)
        content_score = 0
        if gemini_result:
            content_score = gemini_result.get('score', 0)
        factors['content'] = content_score

        # 2. Link Risk (Google Safe Browsing)
        link_score = 0
        if link_results:
            malicious_links = [l for l in link_results if l.get('is_malicious')]
            if malicious_links:
                link_score = max([l.get('risk_score', 0) for l in link_results])
                if link_score < 70: link_score = 90
            else:
                link_score = 0
        factors['links'] = link_score

        # 3. Attachment Risk (VirusTotal)
        attach_score = 0
        if attachment_results:
            malicious_attach = [a for a in attachment_results if a.get('is_malicious')]
            if malicious_attach:
                attach_score = 100
            else:
                attach_score = 0
        factors['attachments'] = attach_score

        # 4. Reputation Risk
        reputation_score = self._check_reputation(sender_email)
        factors['reputation'] = reputation_score

        # Calculate weighted average
        total_score = 0
        for key, weight in self.WEIGHTS.items():
            total_score += factors[key] * weight

        # Apply specific "boosts"
        if factors['attachments'] == 100 or factors['links'] >= 90:
            total_score = max(total_score, 90)

        category = self._get_category(total_score)
        explanation = self._generate_explanation(factors, category)

        return {
            'score': round(total_score, 2),
            'category': category,
            'explanation': explanation,
            'factors': factors
        }

    def _check_reputation(self, email):
        if not email: return 0
        
        suspicious_keywords = ['verify', 'secure', 'login', 'account', 'update', 'banking']
        domain = email.split('@')[-1].lower()
        
        score = 0
        for kw in suspicious_keywords:
            if kw in domain:
                score += 30
        
        if '0' in domain or '1' in domain:
            score += 50
            
        return min(score, 100)

    def _get_category(self, score):
        """
        Production Thresholds (Unified):
        < 40: safe
        40-70: suspicious
        > 70: phishing
        """
        if score < 40: return 'safe'
        if score < 70: return 'suspicious'
        return 'phishing'

    def _generate_explanation(self, factors, category):
        reasons = []
        if factors['attachments'] > 0:
            reasons.append("Malicious file signatures detected in attachments.")
        if factors['links'] >= 50:
            reasons.append("Links in this email are known to host malware or phishing pages.")
        if factors['content'] >= 70:
            reasons.append("Local ML patterns indicate a high probability of phishing intent.")
        elif factors['content'] >= 40:
            reasons.append("The message contains linguistic anomalies typical of deceptive emails.")
            
        if factors['reputation'] >= 50:
            reasons.append("The sender domain appears to be spoofed or untrusted.")
            
        if not reasons:
            if category == 'safe':
                return "This email passed all security checks. No malicious indicators found."
            return f"Low-level anomalies detected in the {category} risk category."
            
        return " ".join(reasons)
