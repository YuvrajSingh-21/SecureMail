# Hybrid Pipeline Architecture

## 1. Normalization Layer
A strict pre-vectorization scrubber that forces unicode standard NFKC, decodes HTML entities, strips tags, and deletes all invisible characters.
## 2. Dual Feature Extraction
Uses `FeatureUnion` to merge standard 1,000-feature word-level TF-IDF with a 1,000-feature `char_wb` (character boundary) n-gram vectorizer. This mathematically bridges the gap when spaces are injected into words.
## 3. Sender Trust Enforcement
Pre-ML routing ensures that known, cryptographically verified senders bypass the ML scoring to enforce 0 False Positives on critical transactional mail.
