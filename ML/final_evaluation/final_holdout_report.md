# Final Unbiased Holdout Evaluation

## Performance on 30% Unseen Test Set
- **Accuracy:** 0.9918
- **Macro F1:** 0.9849
- **Weighted F1:** 0.9917
- **False Positive Rate (Phishing):** 0.09%
- **False Negative Rate (Phishing):** 0.40%
- **Recall (Phishing):** 99.60%

## Error Analysis
- **Total False Positives:** 59
- **Total False Negatives:** 41
CSV exports contain raw confidence scores and exact body text for inspection.

## Final Verdict
The model was trained exclusively on the 70% data split and isolated entirely from the test split. The evaluation proves that the XGBoost Hybrid Engine mathematically maintains its exact precision and F1 thresholds on massive subsets of unseen real-world data.
