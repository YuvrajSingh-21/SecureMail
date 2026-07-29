# Model Card: SecureMail ML Engine v1.0

## Purpose
Real-time detection of Phishing and Spam emails using hybrid structural and semantic extraction.

## Architecture
- **Feature Extraction:** Hybrid Word + Character-Boundary TF-IDF alongside 10 numeric metadata features.
- **Model:** XGBoost Classifier with Sigmoid Probability Calibration.
- **Adversarial Defenses:** Pre-processing HTML unescaping, NFKC normalization, Zero-Width stripping.

## Final Performance
- **Accuracy:** 0.9893
- **Macro F1:** 0.9800
- **Inference Time (10k emails):** 0.1530s

## Known Limitations
- The model can produce False Positives on highly automated transactional emails sharing 'urgency' vocabulary. A pre-ML trusted sender allowlist is mandated.
## Final Verdict
This model is fully calibrated and frozen for production deployment. The next step is Django integration.
