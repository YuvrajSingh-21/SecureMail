# Security Testing & Bypass Report

## 1. Uppercase Evasion
- Detection Rate: 20.0%
## 2. Typos & Homographs (p@ssword)
- Detection Rate: 60.0%
## 3. Zero-Width / Excessive Spacing
- Detection Rate: 0.0%

Conclusion: Excessive spacing bypasses TF-IDF tokenization completely. Typos successfully evade exact-match keyword extractors but structural features often still catch them.
