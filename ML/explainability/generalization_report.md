# Generalization & Anti-Leakage Report

## 1. Feature Leakage Elimination
Corporate specific identifiers (enron, houston) and raw transport headers (mime-version, x-origin) have been successfully blocked at the TF-IDF vectorizer level.
## 2. Safe Class Source-Balancing
Sample weighting via logarithmic inverse-frequency was applied during training. The Enron samples are now mathematically penalized, allowing smaller diverse sources to equally influence the Safe class boundaries.
## 3. Leave-One-Dataset-Out (LODO)
See `cross_dataset_results.csv` for exact performance metrics on entirely unseen data distributions. The model successfully detects phishing even when tested on a completely omitted scam dataset.
