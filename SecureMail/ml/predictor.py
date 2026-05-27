import os
import joblib
import pandas as pd
import numpy as np
import logging
import time
import json
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

class PhishingPredictor:
    def __init__(self):
        # We load from ml/models/ to use the production artifacts
        self.ml_dir = os.path.dirname(__file__)
        self.models_dir = os.path.join(self.ml_dir, 'models')
        self.extractor = FeatureExtractor()
        
        self.label_map = {0: 'SAFE', 1: 'PHISHING', 2: 'SPAM'}
        
        try:
            # Explicitly load from ml/models/ directory
            self.model = joblib.load(os.path.join(self.models_dir, 'phishing_model.pkl'))
            self.vectorizer = joblib.load(os.path.join(self.models_dir, 'vectorizer.pkl'))
            self.is_loaded = True
            logger.info(f"Local ML Engine artifacts loaded from {self.models_dir}")
        except Exception as e:
            logger.error(f"Failed to load ML model artifacts from {self.models_dir}: {str(e)}")
            self.is_loaded = False

    def predict_email(self, subject, body, sender):
        """
        Runs local inference on email components.
        Returns: {score, label, confidence, reasons}
        """
        start_time = time.time()
        
        if not self.is_loaded:
            return self._fail_safe()

        try:
            # 1. Extract Features
            feats = self.extractor.extract_features(subject, body, sender, "", [])
            
            # LOGGING: Print all extracted features for audit
            logger.info(f"\n--- ML AUDIT: {subject[:30]}... ---")
            logger.info(f"Subject: {subject}")
            logger.info(f"Sender: {sender}")
            logger.info(f"URL Count: {feats['url_count']}")
            logger.info(f"Security Hits: {feats['body_security'] + feats['subj_security']}")
            logger.info(f"Marketing Hits: {feats['marketing_count']}")
            
            combined_text = feats.pop('combined_text')
            feats.pop('sender_domain')
            
            # 2. Linguistic Analysis (TF-IDF)
            tfidf_vec = self.vectorizer.transform([combined_text])
            tfidf_df = pd.DataFrame(tfidf_vec.toarray(), columns=self.vectorizer.get_feature_names_out())
            
            # 3. Combine with Metadata
            meta_df = pd.DataFrame([feats])
            X = pd.concat([meta_df, tfidf_df], axis=1)
            
            # 4. Perform Prediction
            probs = self.model.predict_proba(X)[0]
            pred_idx = np.argmax(probs)
            
            logger.info(f"Raw Probabilities: SAFE={probs[0]:.4f}, PHISH={probs[1]:.4f}, SPAM={probs[2]:.4f}")
            
            label = self.label_map.get(pred_idx, 'SAFE')
            confidence = float(probs[pred_idx])
            
            # 5. Calculate Risk Score (0-100)
            phish_prob = probs[1] if len(probs) > 1 else 0
            spam_prob = probs[2] if len(probs) > 2 else 0
            
            # Weighted risk score favoring phishing detection but ignoring small noise
            score = int((phish_prob * 100) + (spam_prob * 30))
            score = min(100, max(0, score))
            
            # FP Mitigation: Internship/Hiring/Marketing demotion
            if feats['marketing_count'] > 0 and label == 'PHISHING' and confidence < 0.9:
                logger.info("FP MITIGATION: Phishing label demoted due to marketing markers.")
                label = 'SUSPICIOUS'
                score = min(score, 60)
            
            if label == 'SAFE' and confidence > 0.8:
                score = min(score, 25)

            # 6. Generate Human-Readable Reasons
            reasons = self._generate_reasons(feats)
            
            latency_ms = (time.time() - start_time) * 1000
            logger.info(f"ML Result: {label} ({score}) | Latency: {latency_ms:.2f}ms")
            
            return {
                "score": score,
                "label": label,
                "confidence": confidence,
                "reasons": reasons
            }

        except Exception as e:
            logger.error(f"Prediction logic failed: {str(e)}", exc_info=True)
            return self._fail_safe()

    def _generate_reasons(self, feats):
        """Map extracted features to human-readable explanations."""
        reasons = []
        
        # We only add reasons if there's actually a technical hit
        if feats.get('subj_urgency', 0) > 0 or feats.get('body_urgency', 0) > 0:
            reasons.append("Contains urgent language")
        
        if feats.get('url_count', 0) > 8:
            reasons.append(f"Excessive number of links ({feats['url_count']})")
            
        if feats.get('shortened_url_count', 0) > 0:
            reasons.append("Contains shortened URLs")
            
        if feats.get('ip_url_count', 0) > 0:
            reasons.append("Links use raw IP addresses")
            
        if feats.get('login_request_indicator', 0) == 1:
            reasons.append("Contains credential reset request")
            
        if feats.get('body_money', 0) > 0 or feats.get('subj_money', 0) > 0:
            reasons.append("Contains financial request")
            
        if feats.get('suspicious_tld_count', 0) > 0:
            reasons.append("Contains links to high-risk domains")
            
        if feats.get('display_name_mismatch', 0) == 1:
            reasons.append("Sender reputation anomaly detected")
            
        return reasons

    def _fail_safe(self):
        return {
            "score": 0,
            "label": "UNKNOWN",
            "confidence": 0,
            "reasons": ["Internal engine error or model not loaded"]
        }
