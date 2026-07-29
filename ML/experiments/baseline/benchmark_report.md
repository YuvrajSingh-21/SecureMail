# Baseline Machine Learning Benchmarks

## 1. Experimental Setup
- **Dataset:** Version 1.0 (248,703 samples)
- **Splits:** Train (174085), Val (37312), Test (37306)
- **Leakage Check:** 0 duplicates across splits.
- **Features:** TF-IDF (1500 max), Meta Features (10 total).

## 2. Model Performance (Test Set)
| Model                   |   Accuracy |   Precision |   Recall |   Macro F1 |   Weighted F1 |   Train Time (s) |   Inference Time (s) |   Model Size (MB) |
|:------------------------|-----------:|------------:|---------:|-----------:|--------------:|-----------------:|---------------------:|------------------:|
| Logistic Regression     |   0.964295 |    0.967976 | 0.964295 |   0.940621 |      0.965231 |        2.13147   |           0.00593448 |         0.0352993 |
| Multinomial Naive Bayes |   0.952635 |    0.952504 | 0.952635 |   0.910129 |      0.950761 |        0.0334396 |           0.00364065 |         0.0696802 |
| Linear SVM              |   0.97676  |    0.9773   | 0.97676  |   0.959548 |      0.976938 |        3.18711   |           0.00372267 |         0.0351381 |
| Random Forest           |   0.959765 |    0.961418 | 0.959765 |   0.932297 |      0.959563 |        3.57016   |           0.0401838  |         8.56847   |
| XGBoost                 |   0.985203 |    0.985194 | 0.985203 |   0.973024 |      0.984997 |       37.7515    |           0.0159957  |         0.407341  |
| LightGBM                |   0.984319 |    0.984265 | 0.984319 |   0.971286 |      0.984098 |       13.0915    |           0.0318868  |         0.564575  |
| CatBoost                |   0.978877 |    0.978768 | 0.978877 |   0.961451 |      0.978532 |       14.5451    |           0.0250132  |         0.171311  |

## 3. Comparison & Strengths
- **Tree Ensembles (XGBoost, LightGBM, Random Forest):** Typically excel at capturing non-linear relationships and combining TF-IDF frequencies with metadata ratios.
- **Linear Models (LR, SVM):** Extremely fast inference and highly interpretable, but can struggle with the highly imbalanced classes unless heavily weighted.
- **Naive Bayes:** Good baseline for text classification but often overconfident and struggles with correlated features.

## 4. Final Recommendation
The best performing baseline model is **XGBoost** with a Macro F1 of **0.9730**.
This model should be carried forward to the optimization phase for hyperparameter tuning.
