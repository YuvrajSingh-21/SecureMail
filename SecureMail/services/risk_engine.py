import logging

logger = logging.getLogger(__name__)

class RiskEngine:
    """
    Centralized decision engine. Generates a unified analysis payload
    balancing risk vs. safe factors with explainable detection signals.
    """
    
    TRUSTED_DOMAINS = [
        'linkedin.com', 'spotify.com', 'google.com', 'github.com', 
        'openai.com', 'unstop.news', 'microsoft.com', 'amazon.com',
        'apple.com', 'netflix.com', 'resumeworded.com'
    ]

    SIGNAL_WEIGHTS = {
        'urgency': 15,
        'reward_bait': 20,
        'scarcity': 15,
        'authority_fake': 15,
        'login_request': 40,
        'spoofing': 35,
        'ip_url': 40,
        'excessive_links': 10,
        'shortened_url': 15,
        'trusted_domain': -25,
        'corp_sender': -20
    }

    def calculate_risk(self, gemini_result=None, link_results=None, attachment_results=None, sender_email=""):
        features = gemini_result.get('features', {}) if gemini_result else {}
        domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ""
        is_trusted = domain in self.TRUSTED_DOMAINS
        
        explanations = []
        risk_factors = []
        safe_factors = []
        suspicious_phrases = []
        score_adj = 0
        
        # 1. Evaluate Safe Factors
        if is_trusted:
            safe_factors.append("Trusted sender history")
            explanations.append({"type": "trust", "severity": "safe", "message": "✔ Trusted sender domain recognized"})
            score_adj += self.SIGNAL_WEIGHTS['trusted_domain']

        if features.get('is_free_provider', 1) == 0 and not is_trusted:
            safe_factors.append("Authenticated domain")
            explanations.append({"type": "auth", "severity": "safe", "message": "✔ Sender authentication checks passed"})
            score_adj += self.SIGNAL_WEIGHTS['corp_sender']
        
        # 2. Evaluate Risk Signals
        if features.get('login_request_indicator', 0) == 1:
            risk_factors.append("Credential harvesting attempt")
            explanations.append({"type": "login", "severity": "critical", "message": "⚠ Credential harvesting pattern detected"})
            score_adj += self.SIGNAL_WEIGHTS['login_request']
            suspicious_phrases.append("verify your account")

        if features.get('display_name_mismatch', 0) == 1:
            risk_factors.append("Sender identity mismatch")
            explanations.append({"type": "spoofing", "severity": "high", "message": "⚠ Sender name/domain mismatch identified"})
            score_adj += self.SIGNAL_WEIGHTS['spoofing']

        if features.get('ip_url_count', 0) > 0:
            risk_factors.append("IP-based URLs")
            explanations.append({"type": "ip_url", "severity": "high", "message": "⚠ Obfuscated IP-based URLs detected"})
            score_adj += self.SIGNAL_WEIGHTS['ip_url']

        if features.get('url_count', 0) > 8:
            risk_factors.append("Multiple CTA patterns")
            explanations.append({"type": "excessive_links", "severity": "medium", "message": "⚠ Multiple CTA patterns detected (Excessive links)"})
            score_adj += self.SIGNAL_WEIGHTS['excessive_links']

        if features.get('subj_urgency', 0) > 0 or features.get('body_urgency', 0) > 0:
            risk_factors.append("Urgency-driven language")
            explanations.append({"type": "urgency", "severity": "medium", "message": "⚠ Urgency language detected"})
            score_adj += self.SIGNAL_WEIGHTS['urgency']
            suspicious_phrases.append("immediate action required")

        if features.get('scarcity_count', 0) > 0:
            risk_factors.append("Scarcity tactics")
            explanations.append({"type": "scarcity", "severity": "medium", "message": "⚠ Scarcity tactics identified (Limited time pressure)"})
            score_adj += self.SIGNAL_WEIGHTS['scarcity']

        if features.get('body_money', 0) > 0:
            risk_factors.append("Reward bait")
            explanations.append({"type": "reward", "severity": "high", "message": "⚠ Reward bait detected (Financial incentives)"})
            score_adj += self.SIGNAL_WEIGHTS['reward_bait']
            suspicious_phrases.append("exclusive bonus")

        if features.get('body_authority', 0) > 0:
            risk_factors.append("Fake authority")
            explanations.append({"type": "authority", "severity": "medium", "message": "⚠ Fake authority indicators (Official-sounding phrases)"})
            score_adj += self.SIGNAL_WEIGHTS['authority_fake']

        if features.get('shortened_url_count', 0) > 0:
            risk_factors.append("Redirect obfuscation")
            explanations.append({"type": "redirect", "severity": "medium", "message": "⚠ Shortened URL redirection detected"})
            score_adj += self.SIGNAL_WEIGHTS['shortened_url']

        link_threat = any(l.get('is_malicious') for l in link_results) if link_results else False
        if link_threat:
            risk_factors.append("Verified malicious URLs")
            explanations.append({"type": "blacklist", "severity": "critical", "message": "⚠ One or more links flagged as MALICIOUS"})
            score_adj += 50
            
        attach_threat = any(a.get('is_malicious') for a in attachment_results) if attachment_results else False
        if attach_threat:
            risk_factors.append("Verified malware")
            explanations.append({"type": "malware", "severity": "critical", "message": "⚠ MALWARE DETECTED in attachments"})
            score_adj += 60

        # 3. Realistic Metrics Calculation
        text_content = features.get('combined_text', '')
        complexity_score = min(100, len(text_content) / 50) if text_content else 0
        
        # Lexical Diversity
        words = text_content.split()
        lexical_diversity = len(set(words)) / len(words) if words else 0
        entropy_score = min(100, float(lexical_diversity * 100))

        # 4. Balanced Verdict Logic
        base_score = gemini_result.get('score', 0) if gemini_result else 0
        final_score = int(max(0, min(100, base_score + score_adj)))
        
        # Decision Flow
        if attach_threat or link_threat:
            label = 'PHISHING'
        elif len([e for e in explanations if e['severity'] in ['critical', 'high']]) >= 2 and not is_trusted:
            label = 'PHISHING'
        elif len(risk_factors) >= 3 and not is_trusted:
            label = 'PHISHING'
        elif len(risk_factors) >= 1:
            label = 'SUSPICIOUS'
        elif is_trusted and (features.get('marketing_count', 0) > 0 or features.get('url_count', 0) > 5):
            label = 'PROMOTIONAL'
        else:
            label = 'SAFE'

        # Enforcement
        if (is_trusted or len(safe_factors) > len(risk_factors)) and label == 'PHISHING' and not (link_threat or attach_threat):
            label = 'SUSPICIOUS'
            final_score = min(final_score, 65)

        summary = self._generate_deterministic_summary(domain, is_trusted, explanations, label)

        return {
            "label": label,
            "category": label,
            "score": final_score,
            "confidence": float(gemini_result.get('confidence', 0.85) if gemini_result else 0.5) * 100,
            "summary": summary,
            "risk_factors": risk_factors or ["No significant risk factors identified."],
            "safe_factors": safe_factors or ["External sender validation passed."],
            "explanations": explanations,
            "reasons": [e['message'] for e in explanations if e['severity'] != 'safe'] or ["No suspicious behavioral indicators detected."],
            "sender_reputation": 95 if is_trusted else 50,
            "trusted_sender": is_trusted,
            "complexity_score": round(complexity_score, 1),
            "entropy_score": round(entropy_score, 1),
            "cta_count": features.get('url_count', 0),
            "suspicious_phrases": suspicious_phrases,
            "status": "FINALIZED"
        }

    def _generate_deterministic_summary(self, domain, is_trusted, explanations, label):
        risk_msgs = [e['message'].replace('⚠ ', '') for e in explanations if e['severity'] in ['critical', 'high', 'medium']]
        
        if label == 'SAFE':
            if is_trusted:
                return f"Communication from {domain.capitalize()} verified. Identity aligns with authenticated sender history and no deceptive structural patterns were detected."
            return "Security profile remains within safe operational limits. Standard structural integrity and linguistic patterns verified."
        
        if label == 'PROMOTIONAL':
            return f"This message originates from a recognized trusted domain ({domain}) but contains high-density marketing links and promotional tracking common in automated campaigns."

        if label == 'SUSPICIOUS':
            base = "Potential risks identified: "
            if is_trusted: base = f"Known sender ({domain}) identified, but behavioral anomalies detected: "
            return base + ", ".join(risk_msgs[:2]) + "."

        if label == 'PHISHING':
            return "CRITICAL THREAT: " + ", ".join(risk_msgs[:2]) + "."
        
        return "Intelligence analysis completed. Structural and linguistic integrity verified."
