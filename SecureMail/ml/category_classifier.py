import os
import joblib
import pandas as pd
import numpy as np
import logging
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

class CategoryClassifier:
    """
    Multi-class classifier for emails (e.g., BANKING, OTP, NEWSLETTER).
    """
    CATEGORIES = [
        'PERSONAL', 'WORK', 'BANKING', 'OTP', 'SECURITY_ALERT',
        'NEWSLETTER', 'MARKETING', 'SOCIAL_MEDIA', 'SHOPPING',
        'TRAVEL', 'JOB', 'INVOICE', 'SPAM', 'PHISHING', 'MALWARE', 'UNKNOWN'
    ]

    def __init__(self):
        self.ml_dir = os.path.dirname(__file__)
        self.extractor = FeatureExtractor()
        
        try:
            self.model = joblib.load(os.path.join(self.ml_dir, 'models', 'category_model.pkl'))
            self.vectorizer = joblib.load(os.path.join(self.ml_dir, 'models', 'vectorizer_cat.pkl'))
            self.is_loaded = True
        except Exception as e:
            logger.warning(f"Category ML models not found or failed to load: {str(e)}. Using fallback heuristic rules.")
            self.is_loaded = False

    def predict_category(self, subject, body, sender_email, sender_name):
        if not self.is_loaded:
            return self._heuristic_fallback(subject, body, sender_email)

        try:
            feats = self.extractor.extract_features(subject, body, sender_email, sender_name, [])
            combined_text = feats.pop('combined_text')
            feats.pop('sender_domain')
            
            # Filter features for ML model (avoid mismatch with new forensic features)
            ml_feats = {k: v for k, v in feats.items() if k not in ['body_authority', 'scarcity_count', 'cta_phrase_count', 'triggered_phrases']}
            
            tfidf_vec = self.vectorizer.transform([combined_text])
            tfidf_df = pd.DataFrame(tfidf_vec.toarray(), columns=self.vectorizer.get_feature_names_out())
            
            meta_df = pd.DataFrame([ml_feats])
            X = pd.concat([meta_df, tfidf_df], axis=1)
            
            probs = self.model.predict_proba(X)[0]
            pred_idx = np.argmax(probs)
            
            return {
                "category": self.CATEGORIES[pred_idx] if pred_idx < len(self.CATEGORIES) else "UNKNOWN",
                "confidence": float(probs[pred_idx])
            }
        except Exception as e:
            logger.error(f"Error during category prediction: {str(e)}")
            return self._heuristic_fallback(subject, body, sender_email)

    def _heuristic_fallback(self, subject, body, sender):
        """Simple rules-based fallback if model is missing or fails."""
        text = f"{subject} {body}".lower()
        if 'invoice' in subject.lower() or 'receipt' in subject.lower():
            return {"category": "INVOICE", "confidence": 0.8}
        if 'code' in text and ('verification' in text or 'otp' in text):
            return {"category": "OTP", "confidence": 0.85}
        if 'unsubscribe' in body.lower():
            return {"category": "NEWSLETTER", "confidence": 0.75}
        if 'bank' in text or 'payment' in text:
            return {"category": "BANKING", "confidence": 0.7}
        
        return {"category": "PERSONAL", "confidence": 0.5}
