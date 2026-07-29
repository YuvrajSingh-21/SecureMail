# Performance & Latency

- **Feature Extraction Time (1k samples):** 0.7745s
- **Inference Time (1k samples):** 0.5177s
- **Model Size:** 0.39 MB

Adding Character N-Grams marginally increased matrix dimensionality but the optimized `XGBoost` and C-backed `scikit-learn` vectorizers handled it effortlessly. Throughput remains well above production requirements.
