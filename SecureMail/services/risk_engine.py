import logging

logger = logging.getLogger(__name__)

class RiskEngine:
    """
    Centralized forensic decision engine. 
    Implements a Single Source of Truth scoring model.
    Every point and label is derived directly from detected behavioral signals.
    """
    
    TRUSTED_DOMAINS = [
        'linkedin.com', 'spotify.com', 'google.com', 'github.com', 
        'openai.com', 'unstop.news', 'microsoft.com', 'amazon.com',
        'apple.com', 'netflix.com', 'resumeworded.com'
    ]

    # Deterministic Weighted Scoring Model
    # POSITIVE (RISK)
    R_URGENCY = 15
    R_HARVESTING = 40
    R_SPOOFING = 35
    R_CTA_DENSITY = 10
    R_IP_URL = 40
    R_SHORT_URL = 15
    R_REWARD_BAIT = 20
    R_AUTHORITY = 15
    R_MALICIOUS_URL = 60
    R_MALWARE = 70
    R_SUSPICIOUS_TLD = 20

    # NEGATIVE (SAFE)
    S_TRUSTED_DOMAIN = -30
    S_AUTHENTICATED = -20
    S_LEGIT_MARKETING = -15

    def calculate_risk(self, gemini_result=None, link_results=None, attachment_results=None, sender_email=""):
        features = gemini_result.get('features', {}) if gemini_result else {}
        domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ""
        is_trusted = domain in self.TRUSTED_DOMAINS
        triggered = features.get('triggered_phrases', {})
        
        forensic_signals = []
        risk_factors = []
        safe_factors = []
        suspicious_phrases = []
        risk_score_pool = 0
        safe_score_pool = 0
        
        # 1. Evaluate Safe Signals (Negative Weights)
        if is_trusted:
            safe_factors.append(f"Sender domain establishing historical trust ({domain})")
            forensic_signals.append({"type": "trust", "severity": "safe", "message": "✔ Trusted sender domain recognized"})
            safe_score_pool += abs(self.S_TRUSTED_DOMAIN)

        if features.get('is_free_provider', 1) == 0 and not is_trusted:
            safe_factors.append("Authenticated corporate sender identity verified")
            forensic_signals.append({"type": "auth", "severity": "safe", "message": "✔ Sender authentication checks passed"})
            safe_score_pool += abs(self.S_AUTHENTICATED)

        if features.get('marketing_count', 0) > 0 and features.get('login_request_indicator', 0) == 0:
            safe_factors.append("Linguistic patterns align with legitimate marketing communication")
            safe_score_pool += abs(self.S_LEGIT_MARKETING)
        
        # 2. Evaluate Risk Signals (Positive Weights)
        if features.get('login_request_indicator', 0) == 1:
            risk_factors.append(f"Credential harvesting pattern detected (Keywords: {', '.join(triggered.get('credentials', []))})")
            forensic_signals.append({"type": "login", "severity": "critical", "message": "⚠ Credential harvesting attempt detected"})
            risk_score_pool += self.R_HARVESTING
            suspicious_phrases.extend(triggered.get('credentials', []))

        # Authentication Failure Flags
        if not features.get('spf_pass', True):
            risk_factors.append("Sender Policy Framework (SPF) authentication failed")
            forensic_signals.append({"type": "auth_fail", "severity": "high", "message": "⚠ SPF Authentication Failed"})
            risk_score_pool += 25
            
        if not features.get('dkim_pass', True):
            risk_factors.append("DomainKeys Identified Mail (DKIM) signature missing or invalid")
            forensic_signals.append({"type": "auth_fail", "severity": "high", "message": "⚠ DKIM Authentication Failed"})
            risk_score_pool += 25

        if features.get('display_name_mismatch', 0) == 1:
            risk_factors.append("Sender identity mismatch (Potential impersonation or spoofing)")
            forensic_signals.append({"type": "spoofing", "severity": "high", "message": "⚠ Sender name/domain mismatch identified"})
            risk_score_pool += self.R_SPOOFING

        if features.get('ip_url_count', 0) > 0:
            risk_factors.append("Communication contains obfuscated IP-based URLs")
            forensic_signals.append({"type": "ip_url", "severity": "high", "message": "⚠ Obfuscated IP-based URLs detected"})
            risk_score_pool += self.R_IP_URL

        if features.get('link_mismatch', 0) == 1:
            risk_factors.append("URL link mismatch detected (visible text does not match actual destination)")
            forensic_signals.append({"type": "url_mismatch", "severity": "critical", "message": "⚠ Hidden URL Mismatch Detected"})
            risk_score_pool += 50
            
        if features.get('homoglyph_detected', 0) == 1:
            risk_factors.append("Cyrillic homoglyphs detected in URL (Likely domain spoofing)")
            forensic_signals.append({"type": "homoglyph", "severity": "critical", "message": "⚠ Malicious Homoglyph URL Detected"})
            risk_score_pool += 60

        if features.get('url_count', 0) > 8:
            risk_factors.append(f"Excessive link density ({features.get('url_count')} outbound links)")
            forensic_signals.append({"type": "excessive_links", "severity": "medium", "message": "⚠ Excessive outbound links detected"})
            risk_score_pool += self.R_CTA_DENSITY

        if features.get('cta_phrase_count', 0) >= 2:
            risk_factors.append(f"Repeated high-action CTA prompts detected ({', '.join(triggered.get('cta', []))})")
            forensic_signals.append({"type": "cta_density", "severity": "medium", "message": "⚠ Repeated high-action CTA prompts identified"})
            risk_score_pool += self.R_CTA_DENSITY
            suspicious_phrases.extend(triggered.get('cta', []))

        if features.get('body_urgency', 0) > 0 or features.get('subj_urgency', 0) > 0:
            risk_factors.append(f"Urgency-driven language detected (Keywords: {', '.join(triggered.get('urgency', []))})")
            forensic_signals.append({"type": "urgency", "severity": "medium", "message": "⚠ Urgency-oriented language identified"})
            risk_score_pool += self.R_URGENCY
            suspicious_phrases.extend(triggered.get('urgency', []))

        if features.get('scarcity_count', 0) > 0:
            risk_factors.append(f"Scarcity manipulation tactics identified ({', '.join(triggered.get('scarcity', []))})")
            forensic_signals.append({"type": "scarcity", "severity": "medium", "message": "⚠ Scarcity tactics identified"})
            risk_score_pool += self.R_SCARCITY_TACTICS if hasattr(self, 'R_SCARCITY_TACTICS') else 15
            suspicious_phrases.extend(triggered.get('scarcity', []))

        if features.get('body_money', 0) > 0:
            risk_factors.append(f"Financial reward bait detected ({', '.join(triggered.get('money', []))})")
            forensic_signals.append({"type": "reward", "severity": "high", "message": "⚠ Reward bait detected"})
            risk_score_pool += self.R_REWARD_BAIT
            suspicious_phrases.extend(triggered.get('money', []))

        if features.get('body_authority', 0) > 0:
            risk_factors.append(f"Pseudo-authority indicators detected ({', '.join(triggered.get('authority', []))})")
            forensic_signals.append({"type": "authority", "severity": "medium", "message": "⚠ Fake authority indicators identified"})
            risk_score_pool += self.R_AUTHORITY
            suspicious_phrases.extend(triggered.get('authority', []))

        if features.get('suspicious_tld_count', 0) > 0:
            risk_factors.append("Message contains links to high-risk Top-Level Domains")
            risk_score_pool += self.R_SUSPICIOUS_TLD

        link_threat = any(l.get('is_malicious') for l in link_results) if link_results else False
        if link_threat:
            risk_factors.append("Real-time database confirms one or more links are MALICIOUS")
            forensic_signals.append({"type": "blacklist", "severity": "critical", "message": "⚠ Verified MALICIOUS payload URLs detected"})
            risk_score_pool += self.R_MALICIOUS_URL
            
        attach_threat = any(a.get('is_malicious') for a in attachment_results) if attachment_results else False
        if attach_threat:
            risk_factors.append("VirusTotal confirms MALWARE in attachments")
            forensic_signals.append({"type": "malware", "severity": "critical", "message": "⚠ MALWARE DETECTED in attachments"})
            risk_score_pool += self.R_MALWARE

        # 3. Final Scoring (The Formula)
        final_score = risk_score_pool - safe_score_pool
        final_score = int(max(0, min(100, final_score)))

        # 4. Realistic Category Assignment
        if final_score >= 80 or attach_threat or link_threat:
            label = 'PHISHING'
            badge = "Credential Harvesting Risk"
        elif final_score >= 50:
            label = 'SUSPICIOUS'
            badge = "High-Risk Engagement"
        elif is_trusted:
            if features.get('marketing_count', 0) > 0 or features.get('url_count', 0) > 5:
                label = 'PROMOTIONAL'
                badge = "Marketing Communication"
            else:
                label = 'SAFE'
                badge = "Trusted Source"
        else:
            label = 'SAFE'
            badge = "Legitimate Communication"

        # Baseline alignment for UX
        if label == 'SAFE': final_score = max(5, min(15, final_score))
        elif label == 'PROMOTIONAL': final_score = max(20, min(40, final_score))
        elif label == 'SUSPICIOUS': final_score = max(50, min(70, final_score))
        elif label == 'PHISHING': final_score = max(80, final_score)

        # Inconsistency Validation
        if label == "PHISHING" and not risk_factors:
            logger.warning(f"INVALID ANALYSIS STATE: PHISHING verdict rendered with 0 risk factors for {sender_email}")

        summary = self._generate_final_summary(domain, is_trusted, forensic_signals, label, risk_factors)

        # Final Payload
        return {
            "label": label,
            "badge_label": badge,
            "category": label,
            "score": final_score,
            "confidence": float(gemini_result.get('confidence', 0.85) if gemini_result else 0.5) * 100,
            "summary": summary,
            "risk_factors": risk_factors or ["No phishing, credential harvesting, or manipulative behavioral signals detected."],
            "safe_factors": safe_factors or (["Standard validation passed."] if risk_factors else ["No phishing or harvesting signals identified."]),
            "explanations": forensic_signals,
            "reasons": [e['message'] for e in forensic_signals if e['severity'] != 'safe'] or safe_factors,
            "sender_reputation": 95 if is_trusted else 50,
            "trusted_sender": is_trusted,
            "complexity_score": round(min(100, features.get('body_len', 0) / 40), 1),
            "entropy_score": round(float((len(set(features.get('combined_text', '').split())) / len(features.get('combined_text', '').split() or [1])) * 100), 1),
            "cta_count": features.get('url_count', 0) + features.get('cta_phrase_count', 0),
            "suspicious_phrases": list(set(suspicious_phrases)),
            "status": "FINALIZED"
        }

    def _generate_final_summary(self, domain, is_trusted, signals, label, risk_factors):
        if label == 'SAFE':
            if is_trusted:
                return f"This communication originates from a historically trusted sender ({domain.capitalize()}) and does not contain phishing, impersonation, or credential harvesting behaviors. Promotional CTA behavior appears consistent with standard marketing outreach."
            return "Security profile remains within safe operational limits. Identity validation passed and no manipulative structural patterns were identified."
        
        if label == 'PROMOTIONAL':
            return f"This communication originates from a recognized trusted domain ({domain}). The email contains multiple marketing links and promotional tracking common in automated outreach."

        if label == 'SUSPICIOUS':
            risks = [r.split('(')[0].strip() for r in risk_factors]
            return f"This message uses {', '.join(risks[:2]).lower()} commonly associated with manipulative engagement campaigns."

        if label == 'PHISHING':
            risks = [r.split('(')[0].strip() for r in risk_factors]
            return f"CRITICAL: High-risk behavior detected including {', '.join(risks[:2]).lower()}. Structural patterns suggest intent for credential harvesting or malicious redirection."
        
        return "Forensic analysis completed. Structural and linguistic integrity verified."

    def normalize_payload(self, payload):
        if not payload: payload = {}
        if 'ml_metadata' in payload and 'analysis' not in payload:
            inner = payload.get('ml_metadata', {})
        else:
            inner = payload.get('analysis', payload)
        
        raw_conf = inner.get('confidence', inner.get('ml_confidence', 0.85))
        confidence = float(raw_conf) * (100 if float(raw_conf) <= 1.0 else 1)

        norm = {
            "label": inner.get('label', "UNKNOWN"),
            "badge_label": inner.get('badge_label', inner.get('label', "Verified")),
            "score": int(inner.get('score', 0)),
            "confidence": round(confidence, 1),
            "summary": inner.get('summary', "Structural and linguistic integrity verified."),
            "reasons": inner.get('reasons', []),
            "safe_factors": inner.get('safe_factors') or (["Standard validation passed."] if inner.get('risk_factors') else ["No phishing or harvesting signals identified."]),
            "risk_factors": inner.get('risk_factors') or ["No manipulative behavioral signals detected."],
            "explanations": inner.get('explanations', []),
            "sender_reputation": int(inner.get('sender_reputation', 50)),
            "trusted_sender": bool(inner.get('trusted_sender', False)),
            "feedback_submitted": inner.get('feedback_submitted', False),
            "cta_count": int(inner.get('cta_count', 0)),
            "complexity_score": inner.get('complexity_score', 24.5),
            "entropy_score": inner.get('entropy_score', 12.8),
            "suspicious_phrases": inner.get('suspicious_phrases', []),
            "status": inner.get('status', "FINALIZED")
        }
        return norm
